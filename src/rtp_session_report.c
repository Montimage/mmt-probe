#include <stdio.h>
#include <string.h>
#include <time.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "processing.h"


#define MAX_MESS 2000

#define TIMEVAL_2_MSEC(tval) ((tval.tv_sec << 10) + (tval.tv_usec >> 10))
/*
void reset_rtp (const ipacket_t * ipacket,mmt_session_t * rtp_session,session_struct_t *temp_session){
    ((rtp_session_attr_t*) temp_session->app_data)->jitter= 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_lost= 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts= 0;
    ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error= 0;
    ((rtp_session_attr_t*) temp_session->app_data)->packets_nb=0;
    ((rtp_session_attr_t*) temp_session->app_data)->ul_packet_count=get_session_ul_packet_count(rtp_session);
    ((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count=get_session_dl_packet_count(rtp_session);
    ((rtp_session_attr_t*) temp_session->app_data)->ul_byte_count=get_session_ul_byte_count(rtp_session);
    ((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count=get_session_dl_byte_count(rtp_session);
    ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_sec = ipacket->p_hdr->ts.tv_sec;
    ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_usec = ipacket->p_hdr->ts.tv_usec;
}
*/
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
                temp_session->app_format_id = probe_context->rtp_id;
                rtp_attr->packets_nb += 1;
                ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_sec = ipacket->p_hdr->ts.tv_sec;
                ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_usec = ipacket->p_hdr->ts.tv_usec;
            } else {
                mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating RTP reporting context");
                //fprintf(stderr, "Out of memory error when creating RTP specific data structure!\n");
            }
        } else if(temp_session->app_format_id == probe_context->rtp_id) {
            ((rtp_session_attr_t*) temp_session->app_data)->packets_nb += 1;
        }
    }
}

void rtp_jitter_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint32_t * jitter = (uint32_t *) attribute->data;
        if (jitter != NULL && temp_session->app_format_id == probe_context->rtp_id) {
            if (*jitter > ((rtp_session_attr_t*) temp_session->app_data)->jitter) {
                ((rtp_session_attr_t*) temp_session->app_data)->jitter = *jitter;
            }
        }
    }


    //sampling RTP
    /*
    char path[128];
    char message[MAX_MESS + 1];

    //IP strings
    char ip_src_str[46];
    char ip_dst_str[46];
    int keep_direction = 1;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    mmt_session_t * rtp_session = get_session_from_packet(ipacket);
    if(rtp_session == NULL) return;

    //FILE * out_file = (probe_context->data_out_file != NULL) ? probe_context->data_out_file : stdout;
    uint64_t session_id = get_session_id(rtp_session);


    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
        keep_direction = is_local_net(temp_session->ipclient.ipv4);
        is_local_net(temp_session->ipserver.ipv4);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }

    uint32_t app_class = PROTO_CLASS_STREAMING;
    if(get_session_content_flags(rtp_session) & MMT_CONTENT_CONVERSATIONAL) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }else if(get_session_ul_data_packet_count(rtp_session) &&  get_session_dl_data_packet_count(rtp_session)) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }


    const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(rtp_session);

    proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(rtp_session), path);

    uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(rtp_session));

    //sampled metrics are calculated every 5 seconds and reported
    if ((ipacket->p_hdr->ts.tv_sec - ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_sec) >= 5) {
        double loss_rate, loss_burstiness = 0, order_error = 0;

        loss_rate = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / (((rtp_session_attr_t*) temp_session->app_data)->nb_lost + ((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));
        if (((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts) {
            loss_burstiness = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts);
        }
        order_error = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error / (((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));

        ((rtp_session_attr_t*) temp_session->app_data)->ul_packet_count=get_session_ul_packet_count(rtp_session)-((rtp_session_attr_t*) temp_session->app_data)->ul_packet_count;
        ((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count=get_session_dl_packet_count(rtp_session)-((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count;
        ((rtp_session_attr_t*) temp_session->app_data)->ul_byte_count=get_session_ul_byte_count(rtp_session)-((rtp_session_attr_t*) temp_session->app_data)->ul_byte_count;
        ((rtp_session_attr_t*) temp_session->app_data)->dl_byte_count=get_session_dl_byte_count(rtp_session)-((rtp_session_attr_t*) temp_session->app_data)->dl_byte_count;


        snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%lu,%"PRIu64",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,\"%s\",%u,%f,%f,%u,%f", // app specific
                MMT_SAMPLED_RTP_APP_REPORT_FORMAT,
                probe_context->probe_id_number,
                probe_context->input_source,
                ipacket->p_hdr->ts.tv_sec,ipacket->p_hdr->ts.tv_usec,
                session_id,
                ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_sec,
                ((rtp_session_attr_t*) temp_session->app_data)->last_report_time_usec,
                (int) temp_session->ipversion,
                ip_dst_str,
                ip_src_str,
                temp_session->serverport,
                temp_session->clientport,
                (unsigned short)temp_session->proto,
                (keep_direction)?((rtp_session_attr_t*) temp_session->app_data)->ul_packet_count:((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count,
                        (keep_direction)?((rtp_session_attr_t*) temp_session->app_data)->dl_packet_count:((rtp_session_attr_t*) temp_session->app_data)->ul_packet_count,
                                (keep_direction)?((rtp_session_attr_t*) temp_session->app_data)->ul_byte_count:((rtp_session_attr_t*) temp_session->app_data)->dl_byte_count,
                                        (keep_direction)?((rtp_session_attr_t*) temp_session->app_data)->dl_byte_count:((rtp_session_attr_t*) temp_session->app_data)->ul_byte_count,
                                                rtt_ms, get_session_retransmission_count(rtp_session),
                                                app_class,
                                                temp_session->contentclass,path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
                                                loss_rate,
                                                loss_burstiness,
                                                ((rtp_session_attr_t*) temp_session->app_data)->jitter, order_error
        );

        message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
        //send_message_to_file ("rtp.flow.report", message);
        if (probe_context->output_to_file_enable==1)send_message_to_file (message);
        if (probe_context->redis_enable==1)send_message_to_redis ("rtp.flow.report", message);

        reset_rtp(ipacket,rtp_session,temp_session);

    }*/
}

void rtp_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * loss = (uint16_t *) attribute->data;
        if (loss != NULL && temp_session->app_format_id == probe_context->rtp_id) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_lost += *loss;
        }
    }
}

void rtp_order_error_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * order_error = (uint16_t *) attribute->data;
        if (order_error != NULL && temp_session->app_format_id == probe_context->rtp_id) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error += *order_error;
        }
    }
}

void rtp_burst_loss_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    if (temp_session != NULL && temp_session->app_data != NULL) {
        uint16_t * burst_loss = (uint16_t *) attribute->data;
        if (burst_loss != NULL && temp_session->app_format_id == probe_context->rtp_id) {
            ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts += 1;
        }
    }
}

void print_rtp_app_format(const mmt_session_t * expired_session, probe_internal_t * iprobe) {
    int keep_direction = 1;
    session_struct_t * temp_session = get_user_session_context(expired_session);
    //common fields
    //format id, timestamp
    //Flow_id, Start timestamp, IP version, Server_Address, Client_Address, Server_Port, Client_Port, Transport Protocol ID,
    //Uplink Packet Count, Downlink Packet Count, Uplink Byte Count, Downlink Byte Count, TCP RTT, Retransmissions,
    //Application_Family, Content Class, Protocol_Path, Application_Name

    char message[MAX_MESS + 1];
    char path[128];
    //proto_hierarchy_to_str(&expired_session->proto_path, path);
    uint64_t session_id = get_session_id(expired_session);
    mmt_probe_context_t * probe_context = get_probe_context_config();

    if (probe_context->thread_nb > 1) {
        session_id <<= probe_context->thread_nb_2_power;
        session_id |= iprobe->instance_id;
    }
    //IP strings
    char ip_src_str[46];
    char ip_dst_str[46];
    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
        keep_direction = is_local_net(temp_session->ipclient.ipv4);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }

    proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(expired_session), path);

    uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(expired_session));

    double loss_rate, loss_burstiness = 0, order_error = 0;
    loss_rate = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / (((rtp_session_attr_t*) temp_session->app_data)->nb_lost + ((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));
    if (((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts) {
        loss_burstiness = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_lost / ((rtp_session_attr_t*) temp_session->app_data)->nb_loss_bursts);
    }
    order_error = (double) ((double) ((rtp_session_attr_t*) temp_session->app_data)->nb_order_error / (((rtp_session_attr_t*) temp_session->app_data)->packets_nb + 1));

    uint32_t app_class = PROTO_CLASS_STREAMING;
    if(get_session_content_flags(expired_session) & MMT_CONTENT_CONVERSATIONAL) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }else if(get_session_ul_data_packet_count(expired_session) &&  get_session_dl_data_packet_count(expired_session)) {
        app_class = PROTO_CLASS_CONVERSATIONAL;
    }

    struct timeval init_time = get_session_init_time(expired_session);
    struct timeval end_time = get_session_last_activity_time(expired_session);
    const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(expired_session);

    snprintf(message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,\"%s\",%u,%f,%f,%u,%f", // app specific
            temp_session->app_format_id, probe_context->probe_id_number, probe_context->input_source, end_time.tv_sec, end_time.tv_usec,
            session_id,
            init_time.tv_sec, init_time.tv_usec,
            (int) temp_session->ipversion,
            ip_dst_str, ip_src_str,
            temp_session->serverport, temp_session->clientport, (unsigned short) temp_session->proto,
            (keep_direction)?get_session_ul_packet_count(expired_session):get_session_dl_packet_count(expired_session),
                    (keep_direction)?get_session_dl_packet_count(expired_session):get_session_ul_packet_count(expired_session),
                            (keep_direction)?get_session_ul_byte_count(expired_session):get_session_dl_byte_count(expired_session),
                                    (keep_direction)?get_session_dl_byte_count(expired_session):get_session_ul_byte_count(expired_session),
                                            rtt_ms, get_session_retransmission_count(expired_session),
                                            app_class,
                                            temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
                                            loss_rate,
                                            loss_burstiness,
                                            ((rtp_session_attr_t*) temp_session->app_data)->jitter, order_error
    );

    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
    //send_message_to_file ("rtp.flow.report", message);
    if (probe_context->output_to_file_enable==1)send_message_to_file (message);
    if (probe_context->redis_enable==1)send_message_to_redis ("rtp.flow.report", message);
    /*
    // Packet loss rate, Packet loss burstiness, max jitter, Order error rate
    fprintf(out_file, "%hu,%lu.%lu,%"PRIu64",%lu.%lu,%u,%s,%s,%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,%s,%u,%f,%f,%u,%f\n", // app specific
        temp_session->app_format_id, end_time.tv_sec, end_time.tv_usec,
        session_id,
        init_time.tv_sec, init_time.tv_usec,
        (int) temp_session->ipversion,
        ip_dst_str, ip_src_str,
        temp_session->serverport, temp_session->clientport, (unsigned short) temp_session->proto,
        (keep_direction)?get_session_ul_packet_count(expired_session):get_session_dl_packet_count(expired_session),
        (keep_direction)?get_session_dl_packet_count(expired_session):get_session_ul_packet_count(expired_session),
        (keep_direction)?get_session_ul_byte_count(expired_session):get_session_dl_byte_count(expired_session),
        (keep_direction)?get_session_dl_byte_count(expired_session):get_session_ul_byte_count(expired_session),
        rtt_ms, get_session_retransmission_count(expired_session),
        //get_application_class_by_protocol_id(expired_session->proto_path.proto_path[expired_session->proto_path.len - 1]),
        //(expired_session->content_flags & MMT_CONTENT_CONVERSATIONAL) ? PROTO_CLASS_CONVERSATIONAL : PROTO_CLASS_STREAMING,
        app_class,
        temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
        loss_rate,
        loss_burstiness,
        ((rtp_session_attr_t*) temp_session->app_data)->jitter, order_error
    );
     */
}


/*
void register_rtp_attributes(void * handler){
    int i=1;
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_VERSION, rtp_version_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_JITTER, rtp_jitter_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_LOSS, rtp_loss_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_UNORDER, rtp_order_error_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_ERROR_ORDER, rtp_order_error_handle, NULL, NULL);
    i &= register_attribute_handler(handler, PROTO_RTP, RTP_BURST_LOSS, rtp_burst_loss_handle, NULL, NULL);
    if(!i) {
        //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
        fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
    }
}
*/
