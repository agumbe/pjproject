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
#ifndef __PJMEDIA_RTT_TEXT_H__
#define __PJMEDIA_RTT_TEXT_H__

/**
 * @file rtt_text.h
 * @brief SDP header file.
 */
#include <pj/os.h>
#include <pjmedia/types.h>
#include <pj/sock.h>
#include <pjmedia/codec.h>
#include <pjmedia/sdp.h>
#include <pjmedia/transport.h>
#include <pjmedia-audiodev/audiodev.h>
#include <pjmedia/stream.h>

/**
 * @defgroup PJMEDIA_SDP SDP Parsing and Data Structure
 * @ingroup PJMEDIA_SESSION
 * @brief SDP data structure representation and parsing
 * @{
 *
 * The basic SDP session descriptor and elements are described in header
 * file <b><pjmedia/sdp.h></b>. This file contains declaration for
 * SDP session descriptor and SDP media descriptor, along with their
 * attributes. This file also declares functions to parse SDP message.
 */


PJ_BEGIN_DECL

struct pjmedia_rtt_send_data {
        unsigned        ts_offset;
        pj_str_t        payload;
};
typedef struct pjmedia_rtt_send_data pjmedia_rtt_send_data;

/**
 * Generic representation of attribute.
 */
/**
 * Generic representation of attribute.
 */
struct pjmedia_rtt_stream
{
        pjmedia_sdp_session *   local_sdp;
        pjmedia_sdp_session *   remote_sdp;
        pjmedia_transport       *transport;	    /* To send/recv RTP/RTCP	*/

        unsigned                sdp_index;

        pj_pool_t * 	pool;
        pjmedia_endpt * 	endpt;

        /* Active? */
        pj_bool_t		 active;	    /* Non-zero if is in call.	*/

        /* Current stream info: */
        pjmedia_stream_info	 si;		    /* Current stream info.	*/

        /* More info: */
        unsigned		 clock_rate;	    /* clock rate		*/
        unsigned		 samples_per_frame; /* samples per frame	*/
        unsigned		 bytes_per_frame;   /* frame size.		*/

        pjmedia_rtt_send_data  rtt_send_data[20];
        pjmedia_rtt_send_data  rtt_redundants[2];
        unsigned               num_rtt_redundants;
        unsigned               num_send_data;

        unsigned               pt;      /* payload type */

        pj_timestamp           start_ts;

        unsigned                marker;
        pj_mutex_t *            lock;

        /* RTP session: */
        pjmedia_rtp_session	 out_sess;	    /* outgoing RTP session	*/
        pjmedia_rtp_session	 in_sess;	    /* incoming RTP session	*/

        /* RTCP stats: */
        pjmedia_rtcp_session    rtcp;		    /* incoming RTCP session.	*/

        void (* 	on_rx_rtt )(void * obj, pj_str_t rtt_text);
        void *                  cb_obj;
        /* Thread: */
        pj_bool_t		 thread_quit_flag;  /* Stop media thread.	*/
        pj_thread_t		*thread;	    /* Media thread.		*/
};

/**
 * @see pjmedia_sdp_attr
 */
typedef struct pjmedia_rtt_stream pjmedia_rtt_stream;

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
        unsigned            pt,
        pjmedia_endpt * 	endpt,
        pjmedia_sdp_session *   local_sdp,
        pjmedia_sdp_session *   remote_sdp,
        unsigned             sdp_index,
        void (* 	on_rx_rtt )(void * obj, pj_str_t rtt_text),
        void *                  cb_obj,
        pjmedia_transport       *transport);

/**
 * start text media stream.
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		status.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_start(pjmedia_rtt_stream* text_stream);

/**
 * send text media control char. 'S' for start of stream, 'B' for backspace, 'N' for new line
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		status.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_send_control(pjmedia_rtt_stream* text_stream, pj_str_t control);

/**
 * send text media stream.
 *
 * @param pool		Pool to create the attribute.
 * @param name		Attribute name.
 * @param value		Optional attribute value.
 *
 * @return		status.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_send_text(pjmedia_rtt_stream* text_stream, pj_str_t payload);

/**
 * stop text media stream.
 *
 * @param text_stream	Stream to stop.
 *
 * @return		pj_status, < 0 for error.
 */
PJ_DECL(pj_status_t) pjmedia_text_stream_stop(pjmedia_rtt_stream* text_stream);


PJ_END_DECL

/**
 * @}
 */

#endif	/* __PJMEDIA_RTT_TEXT_H__ */

