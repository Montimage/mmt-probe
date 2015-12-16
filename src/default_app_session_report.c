#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <errno.h>
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "mmt/tcpip/mmt_tcpip.h"
#include "processing.h"


#define MAX_MESS 2000
#define TIMEVAL_2_MSEC(tval) ((tval.tv_sec << 10) + (tval.tv_usec >> 10))


void print_default_app_format(const mmt_session_t * expired_session,probe_internal_t * iprobe) {
    int keep_direction = 1;
    session_struct_t * temp_session = get_user_session_context(expired_session);
    char message[MAX_MESS + 1];
    char path[128];
    mmt_probe_context_t * probe_context = get_probe_context_config();

    //common fields
    //format id, timestamp
    //Flow_id, Start timestamp, IP version, Server_Address, Client_Address, Server_Port, Client_Port, Transport Protocol ID,
    //Uplink Packet Count, Downlink Packet Count, Uplink Byte Count, Downlink Byte Count, TCP RTT, Retransmissions,
    //Application_Family, Content Class, Protocol_Path, Application_Name

    uint64_t session_id = get_session_id(expired_session);
    if (probe_context->thread_nb > 1) {
        session_id <<= probe_context->thread_nb_2_power;
        session_id |= iprobe->instance_id;
    }
    //jeevan
    temp_session->contentclass = get_content_class_by_content_flags(get_session_content_flags(expired_session));
    //printf("contentclass=%d \t",temp_session->contentclass);

    //IP strings
    char ip_src_str[46];
    char ip_dst_str[46];
    if (temp_session->ipversion == 4) {
        inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
        keep_direction = is_local_net(temp_session->ipclient.ipv4);
        is_local_net(temp_session->ipserver.ipv4);
    } else {
        inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
    }
    //proto_hierarchy_to_str(&expired_session->proto_path, path);
    proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(expired_session), path);

    uint32_t rtt_ms = TIMEVAL_2_MSEC(get_session_rtt(expired_session));

    struct timeval init_time = get_session_init_time(expired_session);
    struct timeval end_time = get_session_last_activity_time(expired_session);
    const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(expired_session);

    snprintf(message, MAX_MESS,
            "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%lu.%lu,%u,\"%s\",\"%s\",%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,\"%s\",%u", // app specific
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
                                            get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
                                            temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]
    );

    message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
    //send_message_to_file ("flow.report", message);
    if (probe_context->output_to_file_enable==1)send_message_to_file (message);
    if (probe_context->redis_enable==1)send_message_to_redis ("flow.report", message);
    /*
    fprintf(out_file, "%hu,%lu.%lu,%"PRIu64",%lu.%lu,%u,%s,%s,%hu,%hu,%hu,%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,%s,%u,\n", // app specific
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
        get_application_class_by_protocol_id(proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]),
        temp_session->contentclass, path, proto_hierarchy->proto_path[(proto_hierarchy->len <= 16)?(proto_hierarchy->len - 1):(16 - 1)]
    );
     */
}
