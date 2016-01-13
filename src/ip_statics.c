#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
//#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "mmt/tcpip/mmt_tcpip.h"

#include "processing.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdlib.h>
#include <errno.h>

//JP reports having id = 100 is for IP  traffic

ip_statistics_t * ip_stat_root = NULL;


/*
 * Get MAC address of an internet interface of the machine running this program
 * @return a string containing MAC address, e.g., ABCDEFGHIJKL
 * return null if fail
 */


int get_host_mac_address(unsigned char **mac_address, char *interfaceName)
{
    struct ifreq ifr;
    unsigned char *mac;
    int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1) return -1;
    strcpy( ifr.ifr_name,  interfaceName);

    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        mac = (unsigned char *) malloc( sizeof(unsigned char ) * 6 );
        memcpy( mac, ifr.ifr_hwaddr.sa_data, 6 );
        *mac_address = mac;
        return 0;
    }
    return 1;
}



/*
 * Compare two ip addresses.
 */
int compare_ip(unsigned char * a, unsigned char * b,int ipversion){
    int i;
    if( a == NULL || b == NULL )
        return 1;
    //segmentation fault if sizeof(a) or b is not according to the protocol ipv4=4, ipv6=16 and no session protocols= 13
    if (ipversion==4){
        for( i=0; i<4; i++ ){
            if( a[i] != b[i] )
                return 1;
        }
    }else if (ipversion==6){
        for( i=0; i<16; i++ ){
            if( a[i] != b[i] )
                return 1;
        }
    } else{
        for( i=0; i<13; i++ ){
            if( a[i] != b[i] )
                return 1;
        }
    }

    return 0;
}

void print_mac( unsigned char *m1, unsigned char *m2 ){
    printf("%s - %s",
            get_prety_mac_address( m1 ),
            get_prety_mac_address( m2 ));
}

uint64_t get_number_active_flows_from_ip(){
    ip_statistics_t *p;
    ip_proto_statistics_t *proto_stats;
    uint64_t number_flows = 0;
    int is_active    = 0;

    p = ip_stat_root;

    //for each pair (src, dst)
    while(p != NULL){
        proto_stats = p->proto_stats;
        is_active = 0;

        //for each protocol of the pair
        while( proto_stats != NULL ){
            if (proto_stats->touched == 1){
                is_active = 1;
                break;
            }
            proto_stats = proto_stats->next;
        }

        if( is_active )
            number_flows ++;

        p = p->next;
    }
    return number_flows;
}

void reset_ip_proto_stat( ip_proto_statistics_t *stats ){
    stats->touched        = 0;
    stats->sessions_count = 0;
    stats->data_volume    = 0;
    stats->payload_volume = 0;
    stats->packets_count  = 0;
    stats->packets_count_direction[0]  = 0;
    stats->packets_count_direction[1]  = 0;
    stats->data_volume_direction[0]    = 0;
    stats->data_volume_direction[1]    = 0;
    stats->payload_volume_direction[0] = 0;
    stats->payload_volume_direction[1] = 0;
}

void iterate_through_ip( mmt_handler_t *mmt_handler ){

    ip_statistics_t *p;
    ip_proto_statistics_t *proto_stats;
    //FILE * out_file = (probe_context->data_out_file != NULL) ? probe_context->data_out_file : stdout;
    char message[MAX_MESS + 1];
    struct timeval ts = get_last_activity_time(mmt_handler);
    uint64_t number_flows=get_number_active_flows_from_ip();
    //uint64_t number_flows=0;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    p = ip_stat_root;
    //for each pair (ip src, ip dst)
    while(p != NULL){
        proto_stats = p->proto_stats;
        //for each protocol of the pair
        while( proto_stats != NULL){
            char path[128];
            char ip_src_str[46]={0};
            char ip_dst_str[46]={0};
            char * src_mac, * dst_mac;
            src_mac = get_prety_mac_address( proto_stats->src_mac );
            dst_mac = get_prety_mac_address( proto_stats->dst_mac );
            if (p->session->ipversion==4) {
                inet_ntop(AF_INET, (void *) p->session->ipsrc, ip_src_str, INET_ADDRSTRLEN);
                inet_ntop(AF_INET, (void *) p->session->ipdst, ip_dst_str, INET_ADDRSTRLEN);
            } else if (p->session->ipversion==6){
                inet_ntop(AF_INET6, (void *) p->session->ipsrc, ip_src_str, INET6_ADDRSTRLEN);
                inet_ntop(AF_INET6, (void *) p->session->ipdst, ip_dst_str, INET6_ADDRSTRLEN);
            }else{
                strncpy(ip_src_str,(char *)p->session->ipsrc,9);
                strncpy(ip_dst_str,(char *)p->session->ipdst,9);
            }
            int proto_id = proto_stats->proto_hierarchy->proto_path[ proto_stats->proto_hierarchy->len - 1 ];
            proto_hierarchy_ids_to_str(proto_stats->proto_hierarchy, path);

            if (proto_stats->touched == 1){
                int valid=0;
                int sslindex;
                valid=snprintf(message, MAX_MESS,
                        "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%u,\"%s\",%"PRIu64",%"PRIi64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%lu.%lu,\"%s\",\"%s\",%"PRIu16",%"PRIu16",\"%s\",\"%s\"",
                        MMT_STATISTICS_FLOW_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ts.tv_sec, ts.tv_usec,
                        p->session->session_id,proto_id, path, number_flows,
                        //Total
                        proto_stats->data_volume, proto_stats->payload_volume,proto_stats->packets_count,
                        //UL
                        proto_stats->data_volume_direction[0], proto_stats->payload_volume_direction[0],proto_stats->packets_count_direction[0],
                        //DL
                        proto_stats->data_volume_direction[1], proto_stats->payload_volume_direction[1],proto_stats->packets_count_direction[1],
                        //Timestamp (seconds.micros) corresponding to the time when the flow was detected (first packet of the flow).
                        proto_stats->start_timestamp.tv_sec, proto_stats->start_timestamp.tv_usec,
                        //IP and MAC addresses
                        ip_dst_str,ip_src_str,p->session->serverport, p->session->clientport,src_mac,dst_mac);
                if (p->session->session_id !=0) {
                    //We should report this only once at the beginning of the flow.
                    if (p->ip_temp_session->app_format_id==probe_context->web_id && p->counter==0) print_initial_web_report(p,message,valid);
                    else if (p->ip_temp_session->app_format_id==probe_context->rtp_id && p->counter==0) print_initial_rtp_report(p,message,valid);
                    else if (p->ip_temp_session->app_format_id==probe_context->ssl_id && p->counter==0) print_initial_ssl_report(p,message,valid);
                    else if (p->ip_temp_session->app_format_id==probe_context->ftp_id && p->counter==0) print_initial_ftp_report(p,message,valid);
                    else if(p->counter==0){
                        sslindex = get_protocol_index_from_session(p->proto_stats->proto_hierarchy, PROTO_SSL);
                        if (sslindex != -1) print_initial_ssl_report(p,message,valid);
                        else print_initial_default_report(p,message,valid);
                    }
                }
                message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
                //send_message_to_file ("protocol.flow.stat", message);
                if (probe_context->output_to_file_enable==1)send_message_to_file (message);
                if (probe_context->redis_enable==1)send_message_to_redis ("protocol.flow.stat", message);

            }
            reset_ip_proto_stat( proto_stats );

            proto_stats = proto_stats->next;
        }
        p = p->next;
    }
}

void get_MAC_address_from_ip(const ipacket_t * ipacket,ip_proto_statistics_t *proto_stats, int direction){

    unsigned char *src = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
    unsigned char *dst = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);
    unsigned char * temp;


    if(direction==0){
        if (src) {
            temp= (unsigned char *) malloc(sizeof (unsigned char)*6);
            memcpy(temp, src, 6);
            proto_stats->src_mac=temp;
        }
        if (dst) {
            temp= (unsigned char *) malloc(sizeof (unsigned char)*6);
            memcpy(temp, dst, 6);
            proto_stats->dst_mac=temp;
        }
    }else if (direction==1){
        if (src) {
            temp= (unsigned char *) malloc(sizeof (unsigned char)*6);
            memcpy(temp, src, 6);
            proto_stats->dst_mac=temp;
        }
        if (dst) {
            temp= (unsigned char *) malloc(sizeof (unsigned char)*6);
            memcpy(temp, dst, 6);
            proto_stats->src_mac=temp;
        }

    }

}

ip_proto_statistics_t *create_and_init_ip_proto_stat( ){
    ip_proto_statistics_t *proto_stats = (ip_proto_statistics_t *)malloc(sizeof(ip_proto_statistics_t));
    //set counters to zero
    reset_ip_proto_stat( proto_stats );

    proto_stats->next = NULL;
    return proto_stats;
}

void update_ip_proto_stat_info( ip_proto_statistics_t *proto_stats, const ipacket_t * ipacket, int direction){

    uint32_t proto_offset, index;
    uint64_t p_data, p_payload;

    if( direction != 0 && direction != 1){
        fprintf(stderr, "Line %d: The direction must be 0 or 1", __LINE__);
        direction = 0;
    }
    index = proto_stats->proto_hierarchy->len -1;
    //offset of the current protocol
    proto_offset = get_packet_offset_at_index( ipacket, index );

    p_data    = ipacket->p_hdr->len;
    p_payload = ipacket->p_hdr->len - proto_offset;

    //first time the flow is detected
    if( proto_stats->touched == 0 ){
        proto_stats->start_timestamp = get_last_activity_time( ipacket->mmt_handler );
        proto_stats->touched         = 1;
    }
    get_MAC_address_from_ip(ipacket,proto_stats,direction);

    proto_stats->data_volume    += p_data;
    proto_stats->payload_volume += p_payload;
    proto_stats->packets_count  += 1;

    proto_stats->data_volume_direction[direction]    += p_data;
    proto_stats->payload_volume_direction[direction] += p_payload;
    proto_stats->packets_count_direction[direction]  += 1;
}

ip_proto_statistics_t * get_ip_proto_stat_for_proto_path(ip_proto_statistics_t *proto, const proto_hierarchy_t *path ){
    ip_proto_statistics_t *p = proto;
    while( p != NULL ){
        if( p->proto_hierarchy->len == path->len ){
            int i = 0, n = path->len;
            for( i=0; i<n; i++ )
                if( p->proto_hierarchy->proto_path[i] != path->proto_path[i] )
                    break;

            if( i == n )
                return p;
        }
        p = p->next;
    }
    return NULL;
}

void update_ip_proto_stat (ip_statistics_t *ip_stat, const ipacket_t * ipacket, int direction){
    ip_proto_statistics_t *root;
    root = ip_stat->proto_stats;

    //update only the leaf
    ip_proto_statistics_t *p = get_ip_proto_stat_for_proto_path( root, ipacket->proto_hierarchy);

    //well, the stat for this proto path does not exist => I will create it
    if( p == NULL){
        p = create_and_init_ip_proto_stat();

        p->proto_hierarchy = malloc( sizeof( proto_hierarchy_t ));
        //copy proto_hierarchy
        memcpy( p->proto_hierarchy, ipacket->proto_hierarchy, sizeof( proto_hierarchy_t ));

        //put this before root
        p->next = ip_stat->proto_stats;
        ip_stat->proto_stats = p;
    }

    update_ip_proto_stat_info( p, ipacket, direction );
}

ip_statistics_t * create_and_init_ip_stat (const ipacket_t * ipacket,unsigned char *src, unsigned char *dst, uint64_t session_id,int ipversion ){

    ip_statistics_t * ip_stat = malloc( sizeof( ip_statistics_t ));
    memset(ip_stat,0,sizeof( ip_statistics_t )); //jeevan

    if (ip_stat != NULL){
        ip_stat->next        = NULL;
        ip_stat->proto_stats = NULL;

        //init session information
        ip_stat->session = malloc( sizeof( ip_statistics_session_t ));
        memset(ip_stat->session,0,sizeof( ip_statistics_session_t )); //jeevan

        ip_stat->session->ipversion=ipversion;

        if(ip_stat->session->ipversion==4){
            unsigned char *tmp;
            tmp = malloc( sizeof( unsigned char )*4 );
            memcpy(tmp, src, 4);
            tmp[4]='\0';
            ip_stat->session->ipsrc = tmp;

            tmp = malloc( sizeof( unsigned char )*4 );
            memcpy(tmp, dst, 4);
            tmp[4]='\0';
            ip_stat->session->ipdst = tmp;
            ip_stat->session->session_id=session_id;
            ip_stat->mmt_session=ipacket->session;

            ip_stat->ip_temp_session = get_user_session_context(ipacket->session);

            uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
            uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
            if (cport) {
                ip_stat->session->clientport = *cport;
            }
            if (dport) {
                ip_stat->session->serverport = *dport;
            }

        }else if(ip_stat->session->ipversion==6){
            unsigned char *tmp;
            tmp = malloc( sizeof( unsigned char )*16 );
            memcpy(tmp, src, 16);
            tmp[16]='\0';
            ip_stat->session->ipsrc = tmp;

            tmp = malloc( sizeof( unsigned char )*16 );
            memcpy(tmp, dst, 16);
            tmp[16]='\0';
            ip_stat->session->ipdst = tmp;
            ip_stat->session->session_id=session_id;
            ip_stat->mmt_session=ipacket->session;
            ip_stat->ip_temp_session = get_user_session_context(ipacket->session);
            uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
            uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
            if (cport) {
                ip_stat->session->clientport = *cport;
            }
            if (dport) {
                ip_stat->session->serverport = *dport;
            }

        }else{
            unsigned char *tmp;
            tmp = malloc( sizeof( unsigned char )*13 );
            memcpy(tmp, src, 13);
            tmp[13]='\0';
            ip_stat->session->ipsrc = tmp;

            tmp = malloc( sizeof( unsigned char )*13 );
            memcpy(tmp, dst, 13);
            tmp[13]='\0';
            ip_stat->session->ipdst = tmp;
            ip_stat->session->session_id = session_id;
            ip_stat->session->clientport = 0;
            ip_stat->session->serverport = 0;
            //ip_stat->ip_temp_session->app_format_id= MMT_SKIP_APP_REPORT_FORMAT;
        }

    }

    return ip_stat;
}

ip_statistics_t * get_ip_stat_for_pair_machine( unsigned char *src, unsigned char *dst,uint64_t session_id, int *direction,int ipversion ){
    ip_statistics_t *p = ip_stat_root;
    while( p != NULL){
        if(  p->session->session_id==session_id){
            if( compare_ip( p->session->ipsrc, src,ipversion ) == 0 &&
                    compare_ip( p->session->ipdst, dst,ipversion ) == 0){
                *direction = 0; //UL
                return p;
            }else{
                *direction = 1; //DL
                return p;
            }
        }
        p = p->next;
    }
    return NULL;
}

void ip_get_session_attr(const ipacket_t * ipacket){

    int ipversion;
    mmt_session_t * session = get_session_from_packet(ipacket);

    //if(ipacket->proto_hierarchy->proto_path[2]==178 || ipacket->proto_hierarchy->proto_path[2]==182){
    if(session != NULL){
        int ipindex = get_protocol_index_by_id(ipacket, PROTO_IP);
        //Process IPv4 flows
        if (ipindex != -1) {
            ipversion=4;
            uint64_t session_id = get_session_id(ipacket->session);
            unsigned char * ip_src = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
            unsigned char * ip_dst = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);
            if( ip_src == NULL || ip_dst == NULL )
                return;

            int direction = 0;	//UL as default
            ip_statistics_t * p = get_ip_stat_for_pair_machine(ip_src, ip_dst,session_id, &direction,ipversion );

            //the statistic for this pair (src, dst) does not exit => I create a new one for them
            if( p == NULL ){
                p = create_and_init_ip_stat( ipacket,ip_src, ip_dst,session_id,ipversion );
                //add p to head of eth_stats;
                p->next       = ip_stat_root;
                ip_stat_root = p;
            }
            update_ip_proto_stat( p, ipacket, direction );

        } else {
            ipversion=6;
            unsigned char * ip_src = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
            unsigned char * ip_dst = (unsigned char *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
            uint64_t session_id = get_session_id(ipacket->session);
            if( ip_src == NULL || ip_dst == NULL )
                return;

            int direction = 0;	//UL as default
            ip_statistics_t * p = get_ip_stat_for_pair_machine( ip_src, ip_dst,session_id, &direction,ipversion );

            //the statistic for this pair (src, dst) does not exit => I create a new one for them
            if( p == NULL ){
                p = create_and_init_ip_stat( ipacket, ip_src, ip_dst,session_id,ipversion );
                //add p to head of eth_stats;
                p->next       = ip_stat_root;
                ip_stat_root = p;
            }

            update_ip_proto_stat( p, ipacket, direction );

        }
    }else {
        ipversion=0;
        char * ip_src = "undefined_src";
        char * ip_dst = "undefined_dst";
        if( ip_src == NULL || ip_dst == NULL )
            return;
        uint64_t session_id = 0;
        int direction = 0;	//UL as default
        ip_statistics_t * p = get_ip_stat_for_pair_machine( (unsigned char *)ip_src, (unsigned char *)ip_dst, session_id, &direction,ipversion );
        //the statistic for this pair (src, dst) does not exit => I create a new one for them
        if( p == NULL ){
            p = create_and_init_ip_stat(ipacket, (unsigned char *)ip_src, (unsigned char *)ip_dst,session_id,ipversion );
            //add p to head of eth_stats;
            p->next       = ip_stat_root;
            ip_stat_root = p;
        }

        update_ip_proto_stat( p, ipacket, direction );
    }
}
void iterate_through_expired_session(ip_statistics_t *p){
    ip_proto_statistics_t *proto_stats;
    char message[MAX_MESS + 1];
    //struct timeval ts = get_last_activity_time(mmt_handler);

    struct timeval now;
    gettimeofday(&now,NULL);

    uint64_t number_flows=get_number_active_flows_from_ip();
    mmt_probe_context_t * probe_context = get_probe_context_config();
    proto_stats = p->proto_stats;
    //for each protocol of the pair
    while( proto_stats != NULL){
        char path[128];
        char ip_src_str[46]={0};
        char ip_dst_str[46]={0};
        char * src_mac, * dst_mac;
        src_mac = get_prety_mac_address( proto_stats->src_mac );
        dst_mac = get_prety_mac_address( proto_stats->dst_mac );
        if (p->session->ipversion==4) {
            inet_ntop(AF_INET, (void *) p->session->ipsrc, ip_src_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, (void *) p->session->ipdst, ip_dst_str, INET_ADDRSTRLEN);
        } else if (p->session->ipversion==6){
            inet_ntop(AF_INET6, (void *) p->session->ipsrc, ip_src_str, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, (void *) p->session->ipdst, ip_dst_str, INET6_ADDRSTRLEN);
        }else{
            strncpy(ip_src_str,(char *)p->session->ipsrc,9);
            strncpy(ip_dst_str,(char *)p->session->ipdst,9);
        }
        int proto_id = proto_stats->proto_hierarchy->proto_path[ proto_stats->proto_hierarchy->len - 1 ];
        proto_hierarchy_ids_to_str(proto_stats->proto_hierarchy, path);

        if (proto_stats->touched == 1){
            int valid=0;
            int sslindex;
            valid=snprintf(message, MAX_MESS,
                    "%u,%u,\"%s\",%lu.%lu,%"PRIu64",%u,\"%s\",%"PRIu64",%"PRIi64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%"PRIi64",%"PRIu64",%lu.%lu,\"%s\",\"%s\",%"PRIu16",%"PRIu16",\"%s\",\"%s\"",
                    MMT_STATISTICS_FLOW_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, now.tv_sec,now.tv_usec,
                    p->session->session_id,proto_id, path, number_flows,
                    //Total
                    proto_stats->data_volume, proto_stats->payload_volume,proto_stats->packets_count,
                    //UL
                    proto_stats->data_volume_direction[0], proto_stats->payload_volume_direction[0],proto_stats->packets_count_direction[0],
                    //DL
                    proto_stats->data_volume_direction[1], proto_stats->payload_volume_direction[1],proto_stats->packets_count_direction[1],
                    //Timestamp (seconds.micros) corresponding to the time when the flow was detected (first packet of the flow).
                    proto_stats->start_timestamp.tv_sec, proto_stats->start_timestamp.tv_usec,
                    //IP and MAC addresses
                    ip_dst_str,ip_src_str,p->session->serverport, p->session->clientport,src_mac,dst_mac);

            if (p->session->session_id !=0) {
                if (p->ip_temp_session->app_format_id==probe_context->web_id && p->counter==0) print_initial_web_report(p,message,valid);
                else if (p->ip_temp_session->app_format_id==probe_context->rtp_id && p->counter==0) print_initial_rtp_report(p,message,valid);
                else if (p->ip_temp_session->app_format_id==probe_context->ssl_id && p->counter==0) print_initial_ssl_report(p,message,valid);
                else if (p->ip_temp_session->app_format_id==probe_context->ftp_id && p->counter==0) print_initial_ftp_report(p,message,valid);
                else if(p->counter==0 && p->session->session_id !=0){
                    sslindex = get_protocol_index_from_session(p->proto_stats->proto_hierarchy, PROTO_SSL);
                    if (sslindex != -1) print_initial_ssl_report(p,message,valid);
                    else print_initial_default_report(p,message,valid);
                }
            }

            message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
            //send_message_to_file ("protocol.flow.stat", message);
            if (probe_context->output_to_file_enable==1)send_message_to_file (message);
            if (probe_context->redis_enable==1)send_message_to_redis ("protocol.flow.stat", message);

        }

        proto_stats = proto_stats->next;
    }

}
void classification_expiry_session(const mmt_session_t * expired_session, void * args) {
    session_struct_t * temp_session = get_user_session_context(expired_session);
    if (temp_session == NULL) {
        return;
    }
    probe_internal_t * iprobe = (probe_internal_t *) args;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    int sslindex;
    uint64_t session_id = get_session_id(expired_session);

    if (is_microflow(expired_session)) {
        microsessions_stats_t * mf_stats = &iprobe->mf_stats[get_session_protocol_hierarchy(expired_session)->proto_path[(get_session_protocol_hierarchy(expired_session)->len <= 16)?(get_session_protocol_hierarchy(expired_session)->len - 1):(16 - 1)]];
        update_microflows_stats(mf_stats, expired_session);
        if (is_microflow_stats_reportable(mf_stats)) {
            report_microflows_stats(mf_stats);
        }
    } else {
        //First we check if we should skip the reporting for this flow
        if (temp_session->app_format_id != MMT_SKIP_APP_REPORT_FORMAT) {
            if (probe_context->web_enable==1 && temp_session->app_format_id==probe_context->web_id)print_web_app_format(expired_session, iprobe);
            else if (probe_context->ssl_enable==1 && temp_session->app_format_id==probe_context->ssl_id)print_ssl_app_format(expired_session, iprobe);
            else if(probe_context->rtp_enable==1 && temp_session->app_format_id==probe_context->rtp_id)print_rtp_app_format(expired_session, iprobe);
            else if(probe_context->ftp_enable==1 &&temp_session->app_format_id==probe_context->ftp_id)print_rtp_app_format(expired_session, iprobe);
            else{
                sslindex = get_protocol_index_from_session(get_session_protocol_hierarchy(expired_session), PROTO_SSL);
                if (sslindex != -1 && probe_context->ssl_enable==1 ) print_ssl_app_format(expired_session, iprobe);
                else print_default_app_format(expired_session,iprobe);

            }

        }
    }

      ip_statistics_t *p;
      ip_statistics_t *HEAD;
      p = ip_stat_root;
      HEAD = ip_stat_root;

      while(p != NULL){
          if (p->session->session_id == session_id){
              iterate_through_expired_session(p);
              if(p==ip_stat_root){
                  if (p->proto_stats!= NULL) {
                      //Free the protocol specific data
                      free(p->proto_stats);
                  }
                  if (p->session!= NULL) {
                      //Free the session specific data
                      free(p->session);
                  }
                  ip_stat_root=p->next;
                  free(p);
                  break;
              }
              HEAD->next=p->next;

              if (p->proto_stats!= NULL) {
                  //Free the protocol specific data
                  free(p->proto_stats);
              }
              if (p->session!= NULL) {
                  //Free the session specific data
                  free(p->session);
              }
              free(p);
              //p=HEAD->next;
              break;

          }else{
              HEAD=p;
              p=p->next;
          }

      }

      if (temp_session->app_data != NULL) {
          //Free the application specific data
          free(temp_session->app_data);
      }
      free(temp_session);
}
