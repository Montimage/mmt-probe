#include <stdio.h>
#include <string.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip_protocols.h"
#include "processing.h"

/* This function resets rtp statistics */
void reset_rtp (session_struct_t *temp_session){
    ((rtp_session_attr_t*) temp_session->app_data)->jitter = 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_lost = 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts = 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error = 0;
    ((rtp_session_attr_t*) temp_session->app_data)->packets_nb = 0;
}

/* This function is called by mmt-dpi for reporting rtp version, if an extraction handler is registered */
void rtp_version_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t * temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    mmt_probe_context_t * probe_context = get_probe_context_config();
    if (temp_session != NULL) {
        if (temp_session->app_data == NULL) {
            rtp_session_attr_t * rtp_attr = (rtp_session_attr_t *) malloc(sizeof (rtp_session_attr_t));
            if (rtp_attr != NULL) {
                memset(rtp_attr, '\0', sizeof (rtp_session_attr_t));
                temp_session->app_data = (void *) rtp_attr;
                temp_session->app_format_id = MMT_RTP_REPORT_FORMAT;
                rtp_attr->packets_nb += 1;
            } else {
                mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating RTP reporting context");
                //fprintf(stderr, "Out of memory error when creating RTP specific data structure!\n");
            }
        } else if(temp_session->app_format_id == MMT_RTP_REPORT_FORMAT) {
            ((rtp_session_attr_t*) temp_session->app_data)->packets_nb += 1;
        }
    }
}

/* This function is called by mmt-dpi for reporting rtp jitter, if an extraction handler is registered */
void rtp_jitter_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint32_t * jitter = (uint32_t *) attribute->data;
        if (jitter != NULL && temp_session->app_format_id == MMT_RTP_REPORT_FORMAT) {
            if (*jitter > ((rtp_session_attr_t*) temp_session->app_data)->jitter) {
                ((rtp_session_attr_t*) temp_session->app_data)->jitter = *jitter;
            }
        }
    }
}

/* This function is called by mmt-dpi for reporting rtp loss, if an extraction handler is registered */
void rtp_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * loss = (uint16_t *) attribute->data;
        if (loss != NULL && temp_session->app_format_id == MMT_RTP_REPORT_FORMAT) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_lost += *loss;
        }
    }
}

/* This function is called by mmt-dpi for reporting rtp order error, if an extraction handler is registered */
void rtp_order_error_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * order_error = (uint16_t *) attribute->data;
        if (order_error != NULL && temp_session->app_format_id == MMT_RTP_REPORT_FORMAT) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error += *order_error;
        }
    }
}

/* This function is called by mmt-dpi for reporting rtp burst loss, if an extraction handler is registered */
void rtp_burst_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * burst_loss = (uint16_t *) attribute->data;
        if (burst_loss != NULL && temp_session->app_format_id == MMT_RTP_REPORT_FORMAT) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts += 1;
        }
    }
}

/* This function is for reporting rtp session statistics*/
void print_initial_rtp_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){
    //case 1://missing dev_prop, cdn_flag

    double loss_rate, loss_burstiness = 0, order_error = 0;
    uint32_t app_class = PROTO_CLASS_STREAMING;
    if(get_session_content_flags(session) & MMT_CONTENT_CONVERSATIONAL) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }else if(get_session_ul_data_packet_count(session) &&  get_session_dl_data_packet_count(session)) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }

    loss_rate = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / (((rtp_session_attr_t*) temp_session->app_data)->nb_lost + ((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));
    if (((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts) {
        loss_burstiness = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts);
    }
    order_error = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error / (((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));

    snprintf(&message[valid], MAX_MESS-valid,
            ",%u,%u,%u,%f,%f,%u,%f", // app specific
            temp_session->app_format_id,
            app_class, temp_session->contentclass,
            loss_rate,
            loss_burstiness,
            ((rtp_session_attr_t*) temp_session->app_data)->jitter, order_error
    );
    reset_rtp(temp_session);
    temp_session->session_attr->touched = 1;
	((rtp_session_attr_t*) temp_session->app_data)->rtp_throughput[0] = 0;
	((rtp_session_attr_t*) temp_session->app_data)->rtp_throughput[1] = 0;
}
