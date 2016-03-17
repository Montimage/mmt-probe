#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "mmt/tcpip/mmt_tcpip.h"
#include "processing.h"

typedef struct http_line_struct {
    const uint8_t *ptr;
    uint16_t len;
} http_line_struct_t;

void ssl_server_name_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    if(ipacket->session == NULL) return;
    session_struct_t *temp_session = (session_struct_t *) get_user_session_context_from_packet(ipacket);
    mmt_probe_context_t * probe_context = get_probe_context_config();

    if (temp_session != NULL) {
        if (temp_session->app_data == NULL) {
            ssl_session_attr_t * ssl_data = (ssl_session_attr_t *) malloc(sizeof (ssl_session_attr_t));
            if (ssl_data != NULL) {
                memset(ssl_data, '\0', sizeof (ssl_session_attr_t));
                temp_session->app_format_id = probe_context->ssl_id;
                temp_session->app_data = (void *) ssl_data;
            } else {
                mmt_log(probe_context, MMT_L_WARNING, MMT_P_MEM_ERROR, "Memory error while creating SSL reporting context");
                //fprintf(stderr, "Out of memory error when creating SSL specific data structure!\n");
                return;
            }
        }
        http_line_struct_t * server_name = (http_line_struct_t *) attribute->data;
        if (server_name != NULL && temp_session->app_format_id == probe_context->ssl_id) {
            uint16_t max = ((uint16_t) server_name->len > 63) ? 63 : server_name->len;
            strncpy(((ssl_session_attr_t *) temp_session->app_data)->hostname, (char *) server_name->ptr, max);
            ((ssl_session_attr_t *) temp_session->app_data)->hostname[max] = '\0';
        }
    }
    temp_session->contentclass = get_content_class_by_content_flags(get_session_content_flags(ipacket->session));
}

void print_ssl_app_format(const mmt_session_t * expired_session,void *args) {
    int keep_direction = 1;
    session_struct_t * temp_session = get_user_session_context(expired_session);
    char message[MAX_MESS + 1];
    char path[128];
    //common fields
    //format id, timestamp
    //Flow_id, Start timestamp, IP version, Server_Address, Client_Address, Server_Port, Client_Port, Transport Protocol ID,
    //Uplink Packet Count, Downlink Packet Count, Uplink Byte Count, Downlink Byte Count, TCP RTT, Retransmissions,
    //Application_Family, Content Class, Protocol_Path, Application_Name
    mmt_probe_context_t * probe_context = get_probe_context_config();

    proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(expired_session), path);
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
        keep_direction = is_localv6_net(ip_src_str);
    }

    temp_session->contentclass = get_content_class_by_content_flags(get_session_content_flags(expired_session));

    uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(expired_session));

    struct timeval init_time = get_session_init_time(expired_session);
    struct timeval end_time = get_session_last_activity_time(expired_session);
    const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(expired_session);

    snprintf(message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%"PRIu32",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,\"%s\",%u,\"%s\",%u", // app specific
            temp_session->app_format_id, probe_context->probe_id_number, probe_context->input_source, end_time.tv_sec, end_time.tv_usec,
            temp_session->session_id,temp_session->thread_number,
            init_time.tv_sec, init_time.tv_usec,
            (int) temp_session->ipversion,
            ip_dst_str, ip_src_str,
            temp_session->serverport, temp_session->clientport, (unsigned short) temp_session->proto,
            (keep_direction)?get_session_ul_packet_count(expired_session):get_session_dl_packet_count(expired_session),
                    (keep_direction)?get_session_dl_packet_count(expired_session):get_session_ul_packet_count(expired_session),
                            (keep_direction)?get_session_ul_byte_count(expired_session):get_session_dl_byte_count(expired_session),
                                    (keep_direction)?get_session_dl_byte_count(expired_session):get_session_ul_byte_count(expired_session),
                                            rtt_ms, get_session_retransmission_count(expired_session),
                                            get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
                                            temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
                                            (((ssl_session_attr_t *) temp_session->app_data) != NULL) ? ((ssl_session_attr_t *) temp_session->app_data)->hostname : "",
                                                    (get_session_content_flags(expired_session) & MMT_CONTENT_CDN) ? 2 : 0
    );

    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
    //send_message_to_file ("ssl.flow.report", message);
    if (probe_context->output_to_file_enable==1)send_message_to_file_thread (message,(void*)args);
    if (probe_context->redis_enable==1)send_message_to_redis ("ssl.flow.report", message);
    /*
    fprintf(out_file, "%hu,%lu.%lu,%"PRIu64",%lu.%lu,%u,%s,%s,%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,%s,%u,%s,%u\n", // app specific
        (uint16_t) MMT_SSL_APP_REPORT_FORMAT, end_time.tv_sec, end_time.tv_usec,
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
        get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
        temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)],
        (((ssl_session_attr_t *) temp_session->app_data) != NULL) ? ((ssl_session_attr_t *) temp_session->app_data)->hostname : "", (get_session_content_flags(expired_session) & MMT_CONTENT_CDN) ? 2 : 0
    );
     */
}
void print_initial_ssl_report(const mmt_session_t * session,session_struct_t * temp_session, char message [MAX_MESS + 1], int valid){

    //case 1://missing dev_prop, cdn_flag
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);

    snprintf(&message[valid], MAX_MESS-valid,//missing CDN
            ",%u,%u,%u,\"%s\",%u", // app specific
            temp_session->app_format_id,get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
            temp_session->contentclass,
            (((ssl_session_attr_t *) temp_session->app_data) != NULL) ? ((ssl_session_attr_t *) temp_session->app_data)->hostname : "",
                    (get_session_content_flags(session) & MMT_CONTENT_CDN) ? 2 : 0

    );
    temp_session->session_attr->touched=1;
}


/*
void register_ssl_attributes(void *handler){
    int i=1;

    i &= register_attribute_handler(handler, PROTO_SSL, SSL_SERVER_NAME, ssl_server_name_handle, NULL, NULL);

    if(!i) {
        //TODO: we need a sound error handling mechanism! Anyway, we should never get here :)
        fprintf(stderr, "Error while initializing MMT handlers and extractions!\n");
    }
}
*/
