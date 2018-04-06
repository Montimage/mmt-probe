/*
 * ip_static.c
 *
 *  Created on: Feb 5, 2016
 *      Author: montimage
 */
#include <stdio.h>
#include <string.h>
#include <time.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"
#include "processing.h"
#include <unistd.h>

/* This function is for reporting session reports */
void print_ip_session_report (const mmt_session_t * session, void *user_args){
	if (is_microflow(session)) {
		return;
	}
	session_struct_t * temp_session = (session_struct_t *) get_user_session_context(session);
	mmt_probe_context_t * probe_context = get_probe_context_config();
	if (temp_session == NULL) {
		return;
	}

	char message[MAX_MESS + 1];
	uint8_t *ea = 0;
	uint64_t report_number;
	char src_mac_pretty [18], dst_mac_pretty [18];
	int keep_direction = 1;
	int valid = 0;
	struct smp_thread *th = (struct smp_thread *) user_args;

	if (temp_session->session_attr == NULL) {
		temp_session->session_attr = (session_stat_t *) malloc(sizeof (session_stat_t));
		memset(temp_session->session_attr, 0, sizeof (session_stat_t));
	}

	// To  check whether the session activity occurs between the reporting time interval
	if (TIMEVAL_2_USEC(mmt_time_diff(temp_session->session_attr->last_activity_time, get_session_last_activity_time(session))) == 0)return; // check the condition if in the last interval there was a protocol activity or not
	//if (get_session_byte_count(session) - temp_session->session_attr->total_byte_count == 0)return;

	// The report number is maintain to synchronize between the reporting time of the probe and MMT-operator report display time.
	if (temp_session->report_counter == th->report_counter){
		report_number = temp_session->report_counter + 1;
        temp_session->report_counter = 0;
	}else {
		report_number = th->report_counter;
	}

	ea = temp_session->src_mac;
	snprintf(src_mac_pretty , 18, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
	ea = temp_session->dst_mac;
	snprintf(dst_mac_pretty , 18, "%02x:%02x:%02x:%02x:%02x:%02x", ea[0], ea[1], ea[2], ea[3], ea[4], ea[5] );
	char ip_src_str[46];
	char ip_dst_str[46];
	if (temp_session->ipversion == 4) {
		inet_ntop(AF_INET, (void *) &temp_session->ipclient.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &temp_session->ipserver.ipv4, ip_dst_str, INET_ADDRSTRLEN);
		keep_direction = is_local_net(temp_session->ipclient.ipv4);
	} else if(temp_session->ipversion == 6) {
		inet_ntop(AF_INET6, (void *) &temp_session->ipclient.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &temp_session->ipserver.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
		keep_direction = is_localv6_net(ip_src_str);//add more condition if any in is_localv6_net function

	}
	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];
	temp_session->session_attr->last_activity_time = get_session_last_activity_time(session);
	temp_session->session_attr->start_time = get_session_init_time(session);
	proto_hierarchy_ids_to_str(get_session_protocol_hierarchy(session), temp_session->path);

	int sslindex;

	const proto_hierarchy_t * proto_path_0 =  get_session_proto_path_direction(session,1);
	proto_hierarchy_ids_to_str(get_session_proto_path_direction(session,1), temp_session->path_ul);

	if (proto_path_0->len == 0){
		temp_session->path_ul[0] = '\0';
	}

	const proto_hierarchy_t * proto_path_1 =  get_session_proto_path_direction(session,0);
	proto_hierarchy_ids_to_str(get_session_proto_path_direction(session,0), temp_session->path_dl);


	if (proto_path_1->len == 0){
		temp_session->path_dl[0] = '\0';
	}
	// Data transfer time calculation
	if (temp_session->dtt_seen == 1){
		struct timeval t1;
		//The download direction is opposite to set_up_direction, the download direction is from server to client
		if (get_session_setup_direction(session) == 1)t1 = get_session_last_data_packet_time_by_direction(session, 0);
		if (get_session_setup_direction(session) == 0)t1 = get_session_last_data_packet_time_by_direction(session, 1);
		temp_session->data_transfer_time =  TIMEVAL_2_USEC(mmt_time_diff(temp_session->dtt_start_time, t1)) ;
		temp_session->dtt_start_time.tv_sec = t1.tv_sec;
		temp_session->dtt_start_time.tv_usec = t1.tv_usec;
	}
	uint64_t active_session_count = get_active_session_count(th->mmt_handler);
	if (keep_direction == 1){
		snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%"PRIu64",%u,\"%s\",\"%s\",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%lu.%06lu,\"%s\",\"%s\",\"%s\",\"%s\",%"PRIu64",%hu,%hu,%"PRIu32",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u",
				MMT_STATISTICS_FLOW_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, temp_session->session_attr->last_activity_time.tv_sec, temp_session->session_attr->last_activity_time.tv_usec, report_number,
				proto_id,
				temp_session->path_ul, temp_session->path_dl,active_session_count,
				get_session_data_cap_volume(session) - temp_session->session_attr->total_byte_count,
				get_session_data_byte_count(session) - temp_session->session_attr->total_data_byte_count,
				get_session_packet_cap_count(session) - temp_session->session_attr->total_packet_count,

				get_session_ul_cap_byte_count(session)- temp_session->session_attr->byte_count[1],
				get_session_ul_data_byte_count(session)- temp_session->session_attr->data_byte_count[1],
				get_session_ul_cap_packet_count(session) - temp_session->session_attr->packet_count[1],

				get_session_dl_cap_byte_count(session) - temp_session->session_attr->byte_count[0],
				get_session_dl_data_byte_count(session) - temp_session->session_attr->data_byte_count[0],
				get_session_dl_cap_packet_count(session) - temp_session->session_attr->packet_count[0],
				temp_session->session_attr->start_time.tv_sec, temp_session->session_attr->start_time.tv_usec,
				ip_src_str, ip_dst_str, src_mac_pretty, dst_mac_pretty,temp_session ->session_id,
				temp_session->serverport, temp_session->clientport,
				temp_session->thread_number,
			    (temp_session->rtt_at_handshake == 0)?TIMEVAL_2_USEC(get_session_rtt(session)):0,
				temp_session->session_attr->rtt_min_usec[1],
				temp_session->session_attr->rtt_min_usec[0],
				temp_session->session_attr->rtt_max_usec[1],
				temp_session->session_attr->rtt_max_usec[0],
				temp_session->session_attr->rtt_avg_usec[1],
				temp_session->session_attr->rtt_avg_usec[0],
				temp_session->data_transfer_time,
				get_session_retransmission_count (session)-temp_session->session_attr->retransmission_count);
	}else{
		snprintf(message, MAX_MESS,"%u,%u,\"%s\",%lu.%06lu,%"PRIu64",%u,\"%s\",\"%s\",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%lu.%06lu,\"%s\",\"%s\",\"%s\",\"%s\",%"PRIu64",%hu,%hu,%"PRIu32",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%u",
				MMT_STATISTICS_FLOW_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, temp_session->session_attr->last_activity_time.tv_sec, temp_session->session_attr->last_activity_time.tv_usec, report_number,
				proto_id,
				temp_session->path_ul,temp_session->path_dl,active_session_count,
				get_session_data_cap_volume(session) - temp_session->session_attr->total_byte_count,
				get_session_data_byte_count(session) - temp_session->session_attr->total_data_byte_count,
				get_session_packet_cap_count(session) - temp_session->session_attr->total_packet_count,

				get_session_ul_cap_byte_count(session)- temp_session->session_attr->byte_count[0],
				get_session_ul_data_byte_count(session)- temp_session->session_attr->data_byte_count[0],
				get_session_ul_cap_packet_count(session) - temp_session->session_attr->packet_count[0],

				get_session_dl_cap_byte_count(session) - temp_session->session_attr->byte_count[1],
				get_session_dl_data_byte_count(session) - temp_session->session_attr->data_byte_count[1],
				get_session_dl_cap_packet_count(session) - temp_session->session_attr->packet_count[1],
				temp_session->session_attr->start_time.tv_sec, temp_session->session_attr->start_time.tv_usec,
				ip_src_str, ip_dst_str, src_mac_pretty, dst_mac_pretty,temp_session ->session_id,
				temp_session->serverport, temp_session->clientport,
				temp_session->thread_number,
			    (temp_session->rtt_at_handshake == 0)?TIMEVAL_2_USEC(get_session_rtt(session)):0,
				temp_session->session_attr->rtt_min_usec[1],
				temp_session->session_attr->rtt_min_usec[0],
				temp_session->session_attr->rtt_max_usec[1],
				temp_session->session_attr->rtt_max_usec[0],
				temp_session->session_attr->rtt_avg_usec[1],
				temp_session->session_attr->rtt_avg_usec[0],
				temp_session->data_transfer_time,
				get_session_retransmission_count (session)-temp_session->session_attr->retransmission_count);
	}
	valid = strlen(message);

	if (temp_session->app_format_id == MMT_WEB_REPORT_FORMAT && probe_context->web_enable == 1) print_initial_web_report(session, temp_session, message,valid);
	else if (temp_session->app_format_id == MMT_RTP_REPORT_FORMAT && probe_context->rtp_enable == 1) print_initial_rtp_report(session, temp_session, message,valid);
	else if (temp_session->app_format_id == MMT_SSL_REPORT_FORMAT && temp_session->session_attr->touched == 0 && probe_context->ssl_enable == 1) print_initial_ssl_report(session, temp_session, message, valid);
	else if (temp_session->app_format_id == MMT_FTP_REPORT_FORMAT && probe_context->ftp_enable == 1) print_initial_ftp_report(session, temp_session, message, valid);
	else if(temp_session->session_attr->touched == 0){
		sslindex = get_protocol_index_from_session(proto_hierarchy, PROTO_SSL);
		if (sslindex != -1 && probe_context->ssl_enable == 1 ){
			temp_session->app_format_id = MMT_SSL_REPORT_FORMAT;
			print_initial_ssl_report(session, temp_session, message, valid);
		}else print_initial_default_report(session, temp_session, message, valid);
	}
	valid = strlen(message);
	message[ valid ] = '\0'; // correct end of string in case of truncated message
        //printf("session=%s\n", message);
	if (probe_context->output_to_file_enable && probe_context->session_output_channel[0])send_message_to_file_thread (message, (void *)user_args);
	if (probe_context->redis_enable && probe_context->session_output_channel[1])send_message_to_redis ("session.flow.report", message);
	if (probe_context->kafka_enable && probe_context->session_output_channel[2])send_msg_to_kafka(probe_context->topic_object->rkt_session, message);

	temp_session->session_attr->retransmission_count = get_session_retransmission_count (session);

	temp_session->session_attr->total_byte_count = get_session_data_cap_volume(session);
	temp_session->session_attr->total_data_byte_count = get_session_data_byte_count(session);
	temp_session->session_attr->total_packet_count = get_session_packet_cap_count(session);

	temp_session->session_attr->byte_count[1] = (keep_direction)?get_session_ul_cap_byte_count(session):get_session_dl_cap_byte_count(session);
	temp_session->session_attr->byte_count[0] = (keep_direction)?get_session_dl_cap_byte_count(session):get_session_ul_cap_byte_count(session);

	temp_session->session_attr->data_byte_count[1] = (keep_direction)?get_session_ul_data_byte_count(session):get_session_dl_data_byte_count(session);
	temp_session->session_attr->data_byte_count[0] = (keep_direction)?get_session_dl_data_byte_count(session):get_session_ul_data_byte_count(session);

	temp_session->session_attr->packet_count[1] = (keep_direction)?get_session_ul_cap_packet_count(session):get_session_dl_cap_packet_count(session);
	temp_session->session_attr->packet_count[0] = (keep_direction)?get_session_dl_cap_packet_count(session):get_session_ul_cap_packet_count(session);

	temp_session->session_attr->rtt_min_usec[1] = 0;
	temp_session->session_attr->rtt_min_usec[0] = 0;
	temp_session->session_attr->rtt_max_usec[1] = 0;
	temp_session->session_attr->rtt_max_usec[0] = 0;
	temp_session->session_attr->rtt_avg_usec[0] = 0;
	temp_session->session_attr->rtt_avg_usec[1] = 0;
	temp_session->session_attr->rtt_counter[0] = 0;
	temp_session->session_attr->rtt_counter[1] =  0;
	temp_session->session_attr->sum_rtt[0] = 0;
	temp_session->session_attr->sum_rtt[1] = 0;
	temp_session->rtt_at_handshake = TIMEVAL_2_USEC(get_session_rtt(session));
}

/* This function calculates Round Trip Time (RTT) for each session */
void ip_rtt_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	mmt_probe_context_t * probe_context = get_probe_context_config();
	if(attribute->data == NULL) return;
	ip_rtt_t ip_rtt = *((ip_rtt_t *)attribute->data);
	session_struct_t *temp_session = get_user_session_context(ip_rtt.session);
	if (temp_session == NULL) {
		return;
	}
	if (temp_session->session_attr == NULL) {
		temp_session->session_attr = (session_stat_t *) malloc(sizeof (session_stat_t));
		memset(temp_session->session_attr, 0, sizeof (session_stat_t));
	}
	uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);

	if (ip_rtt.rtt.tv_sec < 0 || ip_rtt.rtt.tv_usec < 0 )return;

	uint64_t latest_rtt = (uint64_t) TIMEVAL_2_USEC(ip_rtt.rtt);
	if (proto_id != NULL && * proto_id == 6 &&  latest_rtt > 0 ) {
		if (temp_session->session_attr->rtt_min_usec[ip_rtt.direction] == 0){
			temp_session->session_attr->rtt_min_usec[ip_rtt.direction] = latest_rtt;
			temp_session->session_attr->rtt_counter[ip_rtt.direction] = 1;

		} else {
			temp_session->session_attr->rtt_min_usec[ip_rtt.direction] = (temp_session->session_attr->rtt_min_usec[ip_rtt.direction] < latest_rtt) ? temp_session->session_attr->rtt_min_usec[ip_rtt.direction] : latest_rtt;
			temp_session->session_attr->rtt_counter[ip_rtt.direction]++;
		}

		if (temp_session->session_attr->rtt_max_usec[ip_rtt.direction] == 0){
			temp_session->session_attr->rtt_max_usec[ip_rtt.direction] = latest_rtt;

		} else {
			temp_session->session_attr->rtt_max_usec[ip_rtt.direction] = (temp_session->session_attr->rtt_max_usec[ip_rtt.direction] > latest_rtt) ? temp_session->session_attr->rtt_max_usec[ip_rtt.direction] : latest_rtt;
		}
		temp_session->session_attr->sum_rtt[ip_rtt.direction] += latest_rtt;
		temp_session->session_attr->rtt_avg_usec[ip_rtt.direction] = temp_session->session_attr->sum_rtt [ip_rtt.direction]/temp_session->session_attr->rtt_counter[ip_rtt.direction];

	}
}

/*
void throughput(const mmt_session_t * session,session_struct_t * temp_session, int keep_direction, double throughput []){
	uint64_t time_interval;
	uint64_t total_download_time;
	mmt_probe_context_t * probe_context = get_probe_context_config();

	if (temp_session->session_attr->start_time.tv_sec == 0 ){
		temp_session->session_attr->start_time = get_session_init_time(session);
		time_interval = TIMEVAL_2_USEC(mmt_time_diff(temp_session->session_attr->start_time,get_session_last_activity_time(session)));
	}else {
		time_interval = TIMEVAL_2_USEC(mmt_time_diff(temp_session->session_attr->last_activity_time,get_session_last_activity_time(session)));
	}
	if (keep_direction == 1){
		if (get_session_ul_byte_count(session)- temp_session->session_attr->byte_count[1] > 0)throughput[0] = (double) (get_session_ul_byte_count(session)- temp_session->session_attr->byte_count[1])/time_interval;
		if (get_session_dl_byte_count(session)- temp_session->session_attr->byte_count[0] > 0)throughput[1] = (double) (get_session_dl_byte_count(session)- temp_session->session_attr->byte_count[0])/time_interval;
	} else {
		if (get_session_ul_byte_count(session)- temp_session->session_attr->byte_count[0] > 0)throughput[0] = (double)(get_session_ul_byte_count(session)- temp_session->session_attr->byte_count[0])/time_interval;
		if (get_session_dl_byte_count(session)- temp_session->session_attr->byte_count[1] > 0)throughput[1] = (double)(get_session_dl_byte_count(session)- temp_session->session_attr->byte_count[1])/time_interval;
	}

}
*/

