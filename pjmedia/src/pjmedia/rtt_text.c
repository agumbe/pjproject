/* $Id$ */
/*
 * Copyright (C) 2008-2011 Teluu Inc. (http://www.teluu.com)
 * Copyright (C) 2003-2008 Benny Prijono <benny@prijono.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */
#include <pjmedia/stream.h>
#include <pjmedia/errno.h>
#include <pjmedia/rtp.h>
#include <pjmedia/rtcp.h>
#include <pjmedia/jbuf.h>
#include <pj/array.h>
#include <pj/assert.h>
#include <pj/ctype.h>
#include <pj/compat/socket.h>
#include <pj/errno.h>
#include <pj/ioqueue.h>
#include <pj/log.h>
#include <pj/os.h>
#include <pj/pool.h>
#include <pj/rand.h>
#include <pj/sock_select.h>
#include <pj/string.h>	    /* memcpy() */
#include <pjlib.h>
#include <pjmedia/rtt_text.h>


#define THIS_FILE			"rtt_text.c"
#define ERRLEVEL			1
#define LOGERR_(expr)			PJ_PERROR(4,expr);
#define TRC_(expr)			PJ_LOG(5,expr)

static void destroy_call_media(pjmedia_rtt_stream * rtt_stream);
static void on_rx_rtp(void *user_data, void *pkt, pj_ssize_t size);
static void on_rx_rtcp(void *user_data, void *pkt, pj_ssize_t size);
static int media_thread(void *arg);
static void destroy_call_media(pjmedia_rtt_stream * rtt_stream);

#if (defined(PJ_WIN32) && PJ_WIN32 != 0) || (defined(PJ_WIN64) && PJ_WIN64 != 0)
#include <windows.h>
static void boost_priority(void)
{
    SetPriorityClass( GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
}

#elif defined(PJ_LINUX) && PJ_LINUX != 0
#include <pthread.h>
static void boost_priority(void)
{
#define POLICY	SCHED_FIFO
    struct sched_param tp;
    int max_prio;
    int policy;
    int rc;

    if (sched_get_priority_min(POLICY) < sched_get_priority_max(POLICY))
	max_prio = sched_get_priority_max(POLICY)-1;
    else
	max_prio = sched_get_priority_max(POLICY)+1;

    /*
     * Adjust process scheduling algorithm and priority
     */
    rc = sched_getparam(0, &tp);
    if (rc != 0) {
	//app_perror( THIS_FILE, "sched_getparam error",
	//	    PJ_RETURN_OS_ERROR(rc));
	return;
    }
    tp.sched_priority = max_prio;

    rc = sched_setscheduler(0, POLICY, &tp);
    if (rc != 0) {
	//app_perror( THIS_FILE, "sched_setscheduler error",
	//	    PJ_RETURN_OS_ERROR(rc));
    }

    PJ_LOG(4, (THIS_FILE, "New process policy=%d, priority=%d",
	      policy, tp.sched_priority));

    /*
     * Adjust thread scheduling algorithm and priority
     */
    rc = pthread_getschedparam(pthread_self(), &policy, &tp);
    if (rc != 0) {
	//app_perror( THIS_FILE, "pthread_getschedparam error",
	//	    PJ_RETURN_OS_ERROR(rc));
	return;
    }

    PJ_LOG(4, (THIS_FILE, "Old thread policy=%d, priority=%d",
	      policy, tp.sched_priority));

    policy = POLICY;
    tp.sched_priority = max_prio;

    rc = pthread_setschedparam(pthread_self(), policy, &tp);
    if (rc != 0) {
	//app_perror( THIS_FILE, "pthread_setschedparam error",
	//	    PJ_RETURN_OS_ERROR(rc));
	return;
    }

    PJ_LOG(4, (THIS_FILE, "New thread policy=%d, priority=%d",
	      policy, tp.sched_priority));
}

#else
#  define boost_priority()
#endif

/**
 * Create text media stream.
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		The new SDP attribute.
 */

PJ_DECL(pjmedia_rtt_stream*) pjmedia_text_stream_create(pj_pool_t *pool,
        pjmedia_endpt * 	endpt,
        pjmedia_sdp_session *local_sdp,
        pjmedia_sdp_session *remote_sdp,
        unsigned             sdp_index,
        pj_status_t(* 	on_rx_rtt )(void * obj, void *rtt_text, unsigned length, unsigned  ts),
        void *                  cb_obj,
        pjmedia_transport       *transport)
{
        pj_status_t status;
        pjmedia_rtt_stream* rtt_stream;
        rtt_stream = PJ_POOL_ZALLOC_T(pool, pjmedia_rtt_stream);

        if (rtt_stream != NULL) {
                rtt_stream->local_sdp = local_sdp;
                rtt_stream->remote_sdp = remote_sdp;
                rtt_stream->transport = transport;
                rtt_stream->endpt = endpt;
                rtt_stream->sdp_index = sdp_index;
                rtt_stream->pool = pool;
                rtt_stream->on_rx_rtt = on_rx_rtt;
                rtt_stream->cb_obj = cb_obj;

                status = pj_mutex_create_simple(pool, "rtt_text", &rtt_stream->lock);
                if (status != PJ_SUCCESS) {
                        //app_perror(THIS_FILE, "acquiring mutex failed", status);
                        return NULL;
                }
        }

        return rtt_stream;
}


/**
 * Create text media stream.
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		The new SDP attribute.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_start(pjmedia_rtt_stream* text_stream)
{
        pj_status_t status;

        /* If this is a mid-call media update, then destroy existing media */
        if (text_stream->thread != NULL)
                destroy_call_media(text_stream);

        status = pjmedia_stream_info_from_sdp(&text_stream->si, text_stream->pool, text_stream->endpt,
                                  text_stream->local_sdp, text_stream->remote_sdp, 0);
        if (status != PJ_SUCCESS) {
                //app_perror(THIS_FILE, "Error creating stream info from SDP", status);
                return status;
        }

        /* Capture stream definition from the SDP */
        /*
        audio->clock_rate = audio->si.fmt.clock_rate;
        audio->samples_per_frame = audio->clock_rate * codec_desc->ptime / 1000;
        audio->bytes_per_frame = codec_desc->bit_rate * codec_desc->ptime / 1000 / 8;
        */
        text_stream->samples_per_frame = 1;
        text_stream->bytes_per_frame = 1;

        pjmedia_rtp_session_init(&text_stream->out_sess, text_stream->si.tx_pt,
                             pj_rand());
        pjmedia_rtp_session_init(&text_stream->in_sess, text_stream->si.fmt.pt, 0);
        pjmedia_rtcp_init(&text_stream->rtcp, "rtcp", 1000, 1, 0);

        /* Attach media to transport */
        status = pjmedia_transport_attach(text_stream->transport, text_stream,
                                      &text_stream->si.rem_addr,
                                      &text_stream->si.rem_rtcp,
                                      sizeof(pj_sockaddr_in),
                                      &on_rx_rtp,
                                      &on_rx_rtcp);
        if (status != PJ_SUCCESS) {
                //app_perror(THIS_FILE, "Error on pjmedia_transport_attach()", status);
                return status;
        }

        /* Start media transport */
        pjmedia_transport_media_start(text_stream->transport, text_stream->pool, text_stream->local_sdp,
                                        text_stream->remote_sdp, text_stream->sdp_index);

        /* Start media thread. */
        text_stream->thread_quit_flag = 0;
#if PJ_HAS_THREADS
        status = pj_thread_create( text_stream->pool, "media", &media_thread, text_stream,
                               0, 0, &text_stream->thread);
        if (status != PJ_SUCCESS) {
                //app_perror(THIS_FILE, "Error creating media thread", status);
                return status;
        }
#endif

        /* Set the media as active */
        text_stream->active = PJ_TRUE;

        return 0;
}


/**
 * send text media stream.
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		status.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_send_text(pjmedia_rtt_stream* text_stream, pj_str_t payload)
{
        pj_status_t     status;
        pj_str_t        dup_payload;
        if (text_stream == NULL)
                return -1;
        status = pj_mutex_lock(text_stream->lock);
        if (status != PJ_SUCCESS) {
                return -1;
        }
        pj_strdup(text_stream->pool, &dup_payload, &payload);
        text_stream->payloads[text_stream->num_payloads++] = dup_payload;
        pj_mutex_unlock(text_stream->lock);
        return 0;
}


/**
 * stop text media stream.
 *
 * @param text_stream	Stream to stop.
 *
 * @return		pj_status, < 0 for error.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_stop(pjmedia_rtt_stream* text_stream)
{
        if (text_stream == NULL) {
                return -1;
        }
        /* destroy existing media */
        if (text_stream->thread != NULL)
                destroy_call_media(text_stream);

        return 0;
}


/*
 * This callback is called by media transport on receipt of RTP packet.
 */
static void on_rx_rtp(void *user_data, void *pkt, pj_ssize_t size)
{
        struct pjmedia_rtt_stream *strm;
        pj_status_t status;
        const pjmedia_rtp_hdr *hdr;
        const void *payload;
        unsigned payload_len;

        strm = user_data;

        /* Discard packet if media is inactive */
        if (!strm->active)
                return;

        /* Check for errors */
        if (size < 0) {
                //app_perror(THIS_FILE, "RTP recv() error", (pj_status_t)-size);
                return;
        }

        /* Decode RTP packet. */
        status = pjmedia_rtp_decode_rtp(&strm->in_sess,
                                        pkt, (int)size,
                                        &hdr, &payload, &payload_len);
        if (status != PJ_SUCCESS) {
                //app_perror(THIS_FILE, "RTP decode error", status);
                return;
        }

        //PJ_LOG(4,(THIS_FILE, "Rx seq=%d", pj_ntohs(hdr->seq)));

        /* Update the RTCP session. */
        pjmedia_rtcp_rx_rtp(&strm->rtcp, pj_ntohs(hdr->seq),
                        pj_ntohl(hdr->ts), payload_len);

        /* Update RTP session */
        pjmedia_rtp_session_update(&strm->in_sess, hdr, NULL);

        if (strm->on_rx_rtt != NULL) {
                strm->on_rx_rtt(strm->cb_obj, payload, payload_len, pj_ntohl(hdr->ts));
        }
}

/*
 * This callback is called by media transport on receipt of RTCP packet.
 */
static void on_rx_rtcp(void *user_data, void *pkt, pj_ssize_t size)
{
    struct pjmedia_rtt_stream *strm;

    strm = user_data;

    /* Discard packet if media is inactive */
    if (!strm->active)
	return;

    /* Check for errors */
    if (size < 0) {
	//app_perror(THIS_FILE, "Error receiving RTCP packet",(pj_status_t)-size);
	return;
    }

    /* Update RTCP session */
    pjmedia_rtcp_rx_rtcp(&strm->rtcp, pkt, size);
}


/*
 * Media thread
 *
 * This is the thread to send and receive both RTP and RTCP packets.
 */
static int media_thread(void *arg)
{
        enum { RTCP_INTERVAL = 5000, RTCP_RAND = 2000 };
        struct pjmedia_rtt_stream *strm = arg;
        char packet[1500];
        unsigned msec_interval;
        pj_timestamp freq, next_rtp, next_rtcp;

        /* Boost thread priority if necessary */
        /* tenp commented */
        //boost_priority();

        /* Let things settle */
        pj_thread_sleep(100);

        msec_interval = strm->samples_per_frame * 1000 / strm->clock_rate;
        pj_get_timestamp_freq(&freq);

        pj_get_timestamp(&next_rtp);
        next_rtp.u64 += (freq.u64 * msec_interval / 1000);

        next_rtcp = next_rtp;
        next_rtcp.u64 += (freq.u64 * (RTCP_INTERVAL+(pj_rand()%RTCP_RAND)) / 1000);

        while (!strm->thread_quit_flag) {
                pj_timestamp now, lesser;
                pj_time_val timeout;
                pj_bool_t send_rtp, send_rtcp;

                send_rtp = send_rtcp = PJ_FALSE;

                /* Determine how long to sleep */
                if (next_rtp.u64 < next_rtcp.u64) {
                        lesser = next_rtp;
                        send_rtp = PJ_TRUE;
                } else {
                        lesser = next_rtcp;
                        send_rtcp = PJ_TRUE;
                }

                pj_get_timestamp(&now);
                if (lesser.u64 <= now.u64) {
                        timeout.sec = timeout.msec = 0;
                        //printf("immediate "); fflush(stdout);
                } else {
                        pj_uint64_t tick_delay;
                        tick_delay = lesser.u64 - now.u64;
                        timeout.sec = 0;
                        timeout.msec = (pj_uint32_t)(tick_delay * 1000 / freq.u64);
                        pj_time_val_normalize(&timeout);

                        //printf("%d:%03d ", timeout.sec, timeout.msec); fflush(stdout);
                }

                /* Wait for next interval */
                //if (timeout.sec!=0 && timeout.msec!=0) {
                        pj_thread_sleep(PJ_TIME_VAL_MSEC(timeout));
                        if (strm->thread_quit_flag)
                        break;
                //}

                pj_get_timestamp(&now);

                if (send_rtp || next_rtp.u64 <= now.u64) {
                /*
                * Time to send RTP packet.
                */
                        if (strm->num_payloads > 0) {
                                pj_status_t status;
                                const void *p_hdr;
                                const pjmedia_rtp_hdr *hdr;
                                pj_ssize_t size;
                                int hdrlen;

                                /* Format RTP header */
                                status = pjmedia_rtp_encode_rtp( &strm->out_sess, strm->si.tx_pt,
                                                             strm->marker, /* marker bit */
                                                             strm->bytes_per_frame,
                                                             strm->samples_per_frame,
                                                             &p_hdr, &hdrlen);
                                strm->marker = 0;
                                if (status == PJ_SUCCESS) {

                                        //PJ_LOG(4,(THIS_FILE, "\t\tTx seq=%d", pj_ntohs(hdr->seq)));

                                        hdr = (const pjmedia_rtp_hdr*) p_hdr;

                                        /* Copy RTP header to packet */
                                        pj_memcpy(packet, hdr, hdrlen);

                                        /* Zero the payload */
                                        pj_bzero(packet+hdrlen, strm->bytes_per_frame);

                                        status = pj_mutex_lock(strm->lock);
                                        if (status == PJ_SUCCESS) {
                                                pj_str_t  payload = strm->payloads[strm->num_payloads--];
                                                pj_memcpy(packet+hdrlen, payload.ptr, payload.slen);

                                                pj_mutex_unlock(strm->lock);

                                                /* Send RTP packet */
                                                size = hdrlen + strm->bytes_per_frame;
                                                status = pjmedia_transport_send_rtp(strm->transport,
                                                                            packet, size);
                                                //if (status != PJ_SUCCESS)
                                                //        app_perror(THIS_FILE, "Error sending RTP packet", status);

                                        }
                                } else {
                                        strm->marker = 1;
                                }
                        } else {
                                pj_assert(!"RTP encode() error");
                        }

                        /* Update RTCP SR */
                        pjmedia_rtcp_tx_rtp( &strm->rtcp, (pj_uint16_t)strm->bytes_per_frame);

                        /* Schedule next send */
                        next_rtp.u64 += (msec_interval * freq.u64 / 1000);
                }

                if (send_rtcp || next_rtcp.u64 <= now.u64) {
                        /*
                        * Time to send RTCP packet.
                        */
                        void *rtcp_pkt;
                        int rtcp_len;
                        pj_ssize_t size;
                        pj_status_t status;

                        /* Build RTCP packet */
                        pjmedia_rtcp_build_rtcp(&strm->rtcp, &rtcp_pkt, &rtcp_len);

                        /* Send packet */
                        size = rtcp_len;
                        status = pjmedia_transport_send_rtcp(strm->transport,
                                                         rtcp_pkt, size);
                        if (status != PJ_SUCCESS) {
                                //app_perror(THIS_FILE, "Error sending RTCP packet", status);
                        }

                        /* Schedule next send */
                        next_rtcp.u64 += (freq.u64 * (RTCP_INTERVAL+(pj_rand()%RTCP_RAND)) /
                                      1000);
                }
        }

        return 0;
}


/* Destroy call's media */
static void destroy_call_media(pjmedia_rtt_stream * rtt_stream)
{
    if (rtt_stream) {
	rtt_stream->active = PJ_FALSE;

	if (rtt_stream->thread) {
	    rtt_stream->thread_quit_flag = 1;
	    pj_thread_join(rtt_stream->thread);
	    pj_thread_destroy(rtt_stream->thread);
	    rtt_stream->thread = NULL;
	    rtt_stream->thread_quit_flag = 0;
	}

	pjmedia_transport_detach(rtt_stream->transport, rtt_stream);
    }
}


