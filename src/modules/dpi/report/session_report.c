/*
 * session_report.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#include <arpa/inet.h>
#include "session_report.h"

//functions implemented by session_report_xxx.c
int print_web_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_ssl_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_rtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);

#ifndef SIMPLE_REPORT
//This callback is called by DPI periodically
static inline void _print_ip_session_report (const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context){
	uint64_t ul_packets = get_session_ul_cap_packet_count(dpi_session);
	uint64_t dl_packets = get_session_dl_cap_packet_count(dpi_session);
	uint64_t total_packets = ul_packets + dl_packets;

	// check the condition if in the last interval there was a protocol activity or not
	// => no new packets since the last report times
	if( total_packets == (session_stat->packets.upload + session_stat->packets.download) )
		return;

	uint64_t ul_volumes = get_session_ul_cap_byte_count(dpi_session);
	uint64_t dl_volumes = get_session_dl_cap_byte_count(dpi_session);
	uint64_t total_volumes = ul_volumes + dl_volumes;

	uint64_t ul_payload = get_session_ul_data_byte_count(dpi_session);
	uint64_t dl_payload = get_session_dl_data_byte_count(dpi_session);
	uint64_t total_payload = ul_payload + dl_payload;

	uint64_t report_number;

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];

	uint64_t data_transfer_time = 0;
	// Data transfer time calculation
	if (session_stat->dtt_seen ){
		struct timeval t1;
		//The download direction is opposite to set_up_direction, the download direction is from server to client
		if (get_session_setup_direction(dpi_session) == 1)
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 0);
		else
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 1);

		data_transfer_time =  u_second_diff(&t1, &session_stat->dtt_start_time);
		session_stat->dtt_start_time = t1;
	}

	char path_ul[128], path_dl[128];

	dpi_proto_hierarchy_ids_to_str(
			get_session_proto_path_direction( dpi_session, 1 ),
			path_ul, sizeof( path_ul) );

	dpi_proto_hierarchy_ids_to_str(
			get_session_proto_path_direction( dpi_session, 0 ),
			path_dl, sizeof( path_dl ));

	uint64_t total_active_sessions = get_active_session_count( context->dpi_handler );

	struct timeval rtt_time = get_session_rtt(dpi_session);
	uint64_t rtt_at_handshake = u_second( &rtt_time );

	uint64_t total_retrans = get_session_retransmission_count( dpi_session );

	struct timeval start_time = get_session_init_time(dpi_session);

	char message[ MAX_LENGTH_REPORT_MESSAGE ];

	int valid = snprintf(message, MAX_LENGTH_REPORT_MESSAGE,
			"%zu," //index of a stat period
			"%u,"  //protocol
			"\"%s\",\"%s\"," //upload - download path
			"%"PRIu64","    //active sessions count
			"%"PRIu64",%"PRIu64",%"PRIu64"," //data, payload, packets
			"%"PRIu64",%"PRIu64",%"PRIu64"," // upload  data, payload, packets
			"%"PRIu64",%"PRIu64",%"PRIu64"," //download data, payload, packets
			"%lu.%06lu," //start timestamp of this session
			"\"%s\",\"%s\"," //ip src - dst
			"\""PRETTY_MAC_FORMAT"\",\""PRETTY_MAC_FORMAT"\"," //mac src - dst
			"%"PRIu64"," //session_id
			"%hu,%hu,"   //port src dst
			"%u,"        //thread_id
			"%"PRIu64"," //rtt
			"%"PRIu64",%"PRIu64"," //rtt min dst, src
			"%"PRIu64",%"PRIu64"," //rtt max dst, src
			"%"PRIu64",%"PRIu64"," //rtt avg dst, src
			"%"PRIu64"," //data transfer time
			"%"PRIu64"," //retransmission
			"%d," //format of the next app report, either http, ssl, ftp, rtp
			"%d,%d", //app family, content class
			context->stat_periods_index,
			proto_id,
			path_ul, path_dl,
			total_active_sessions,

			total_volumes - (session_stat->volumes.upload + session_stat->volumes.download),
			total_payload - (session_stat->payload.upload + session_stat->payload.download),
			total_packets - (session_stat->packets.upload + session_stat->packets.download),

			ul_volumes - session_stat->volumes.upload,
			ul_payload - session_stat->payload.upload,
			ul_packets - session_stat->packets.upload,

			dl_volumes - session_stat->volumes.download,
			dl_payload - session_stat->payload.download,
			dl_packets - session_stat->packets.download,

			start_time.tv_sec, start_time.tv_usec,
			session_stat->ip_src.ip_string, session_stat->ip_dst.ip_string,
			MAC_ELEMENT( session_stat->mac_src ),//src_mac_pretty,
			MAC_ELEMENT( session_stat->mac_dst ),//dst_mac_pretty,
			get_session_id( dpi_session ),
			session_stat->port_dst, session_stat->port_src,

			context->worker_index, //thread_id

			((session_stat->rtt_at_handshake == 0)? rtt_at_handshake : 0),
			session_stat->rtt_min_usec[1],
			session_stat->rtt_min_usec[0],
			session_stat->rtt_max_usec[1],
			session_stat->rtt_max_usec[0],
			session_stat->rtt_avg_usec[1],
			session_stat->rtt_avg_usec[0],

			data_transfer_time,
			(total_retrans - session_stat->retransmission_count),

			session_stat->app_type,

			get_application_class_by_protocol_id( proto_id ),
			session_stat->content_class
	);

	//get_application_class_by_protocol_id( session->proto_id )
	//append stats of application beyond IP
	switch( session_stat->app_type ){
	case SESSION_STAT_TYPE_APP_IP:
		break;
	case SESSION_STAT_TYPE_APP_WEB:
		valid += print_web_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
				dpi_session, session_stat, context );
		break;
	case SESSION_REPORT_SSL_TYPE:
		valid += print_ssl_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
						dpi_session, session_stat, context );
		break;
	case SESSION_REPORT_FTP_TYPE:
		break;
	case SESSION_REPORT_RTP_TYPE:
		valid += print_rtp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
						dpi_session, session_stat, context );
		break;
	default:
		DEBUG("Does not support stat_type = %d", session_stat->app_type );
	}

	struct timeval timestamp = get_session_last_activity_time( dpi_session );

	output_write_report( context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			//timestamp is the one of the last packet in the session
			& timestamp,
			message );

	//remember the current statistics
	session_stat->retransmission_count = total_retrans;

	session_stat->volumes.upload = ul_volumes;
	session_stat->volumes.download = dl_volumes;

	session_stat->payload.upload = ul_payload;
	session_stat->payload.download = dl_payload;

	session_stat->packets.upload = ul_packets;
	session_stat->packets.download = dl_packets;

	session_stat->rtt_min_usec[1] = 0;
	session_stat->rtt_min_usec[0] = 0;
	session_stat->rtt_max_usec[1] = 0;
	session_stat->rtt_max_usec[0] = 0;
	session_stat->rtt_avg_usec[0] = 0;
	session_stat->rtt_avg_usec[1] = 0;
	session_stat->rtt_counter[0]  = 0;
	session_stat->rtt_counter[1]  = 0;
	session_stat->sum_rtt[0]      = 0;
	session_stat->sum_rtt[1]      = 0;
	session_stat->rtt_at_handshake     = rtt_at_handshake;
}


#else
////===> Simpler reports for MMT-Box <===////

//This callback is called by DPI periodically
static inline void _print_ip_session_report (const mmt_session_t * dpi_session, session_stat_t * session, const dpi_context_t *context){

	uint64_t ul_volumes = get_session_ul_cap_byte_count(dpi_session);
	uint64_t dl_volumes = get_session_dl_cap_byte_count(dpi_session);

	if( unlikely( ul_volumes + dl_volumes == 0 ))
		return;

	struct timeval last_activity_time = get_session_last_activity_time( dpi_session );

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];

	char app_path[128];

	dpi_proto_hierarchy_ids_to_str(
			proto_hierarchy,
			app_path, sizeof( app_path) );

	output_write_report_with_format(
			context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			&last_activity_time,

			"%zu," //index of a stat period
			"%d,"
			"\"%s\"," //proto path
			"%"PRIu64",%"PRIu64"," //upload, download volume
			"\"%s\",\"%s\"," //ip src - dst
			"\""PRETTY_MAC_FORMAT"\",\""PRETTY_MAC_FORMAT"\"," //mac src - dst
			"%hu,%hu"   //port src dst
			,
			context->stat_periods_index,
			proto_id,
			app_path,

			ul_volumes - session->volumes.upload,
			dl_volumes - session->volumes.download,

			session->ip_src.ip_string, session->ip_dst.ip_string,

			MAC_ELEMENT( session->mac_src ),//src_mac_pretty,
			MAC_ELEMENT( session->mac_dst ),//dst_mac_pretty,

			session->port_dst, session->port_src
	);

	session->volumes.upload = ul_volumes;
	session->volumes.download = dl_volumes;
}
#endif
//
///* This function calculates Round Trip Time (RTT) for each session */
//void ip_rtt_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
//
//	mmt_probe_context_t * probe_context = get_probe_context_config();
//	if(attribute->data == NULL) return;
//	ip_rtt_t ip_rtt = *((ip_rtt_t *)attribute->data);
//	session_struct_t *temp_session = get_user_session_context(ip_rtt.session);
//	if (temp_session == NULL) {
//		return;
//	}
//	if (temp_session->stat == NULL) {
//		temp_session->stat = (temp_session_statistics_t *) malloc(sizeof (temp_session_statistics_t));
//		memset(temp_session->stat, 0, sizeof (temp_session_statistics_t));
//	}
//	uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);
//
//	if (ip_rtt.rtt.tv_sec < 0 || ip_rtt.rtt.tv_usec < 0 )return;
//
//	uint64_t latest_rtt = (uint64_t) TIMEVAL_2_USEC(ip_rtt.rtt);
//	if (proto_id != NULL && * proto_id == 6 &&  latest_rtt > 0 ) {
//		if (temp_session->stat.rtt_min_usec[ip_rtt.direction] == 0){
//			temp_session->stat.rtt_min_usec[ip_rtt.direction] = latest_rtt;
//			temp_session->stat.rtt_counter[ip_rtt.direction] = 1;
//
//		} else {
//			temp_session->stat.rtt_min_usec[ip_rtt.direction] = (temp_session->stat.rtt_min_usec[ip_rtt.direction] < latest_rtt) ? temp_session->stat.rtt_min_usec[ip_rtt.direction] : latest_rtt;
//			temp_session->stat.rtt_counter[ip_rtt.direction]++;
//		}
//
//		if (temp_session->stat.rtt_max_usec[ip_rtt.direction] == 0){
//			temp_session->stat.rtt_max_usec[ip_rtt.direction] = latest_rtt;
//
//		} else {
//			temp_session->stat.rtt_max_usec[ip_rtt.direction] = (temp_session->stat.rtt_max_usec[ip_rtt.direction] > latest_rtt) ? temp_session->stat.rtt_max_usec[ip_rtt.direction] : latest_rtt;
//		}
//		temp_session->stat.sum_rtt[ip_rtt.direction] += latest_rtt;
//		temp_session->stat.rtt_avg_usec[ip_rtt.direction] = temp_session->stat.sum_rtt [ip_rtt.direction]/temp_session->stat.rtt_counter[ip_rtt.direction];
//
//	}
//}


session_stat_t *session_report_callback_on_starting_session ( const ipacket_t * ipacket ){
	mmt_session_t * dpi_session = ipacket->session;
	if(dpi_session == NULL) return NULL;

	session_stat_t *session_stat = mmt_alloc_and_init_zero( sizeof (session_stat_t));

#ifndef SIMPLE_REPORT
	session_stat->app_type    = SESSION_STAT_TYPE_APP_IP;
#endif
	// Flow extraction
	int ip_index = get_protocol_index_by_id(ipacket, PROTO_IP);

	uint8_t *src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
	uint8_t *dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);

	if (src)
		assign_6bytes( session_stat->mac_src, src );
	if (dst)
		assign_6bytes( session_stat->mac_dst, dst );

	//IPV4
	if (ip_index != -1) {

		uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
		uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);

		if (ip_src)
			session_stat->ip_src.ipv4 = *ip_src;

		if (ip_dst)
			session_stat->ip_dst.ipv4 = (*ip_dst);


		inet_ntop(AF_INET, (void *) &session_stat->ip_src.ipv4, session_stat->ip_src.ip_string, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &session_stat->ip_dst.ipv4, session_stat->ip_dst.ip_string, INET_ADDRSTRLEN);

		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
		if (cport)
			session_stat->port_src = *cport;

		if (dport)
			session_stat->port_dst = *dport;

	} else {
		void * ipv6_src = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
		void * ipv6_dst = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
		if (ipv6_src) {
			memcpy(&session_stat->ip_src.ipv6, ipv6_src, 16);
		}
		if (ipv6_dst) {
			memcpy(&session_stat->ip_dst.ipv6, ipv6_dst, 16);
		}

		inet_ntop(AF_INET6, (void *) &session_stat->ip_src.ipv6, session_stat->ip_src.ip_string, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &session_stat->ip_dst.ipv6, session_stat->ip_dst.ip_string, INET6_ADDRSTRLEN);


		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
		if (cport)
			session_stat->port_src = *cport;
		if (dport)
			session_stat->port_dst = *dport;
	}

	return session_stat;
}


/* This function is called by mmt-dpi for each session time-out (expiry).
 * It provides the expired session information and frees the memory allocated.
 * */
void session_report_callback_on_ending_session(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context ) {
	if (session_stat == NULL)
		return;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//release memory being allocated for application stat (web, ftp, rtp, ssl)
	switch( session_stat->app_type ){
	default:
		break;
	}

	//
	mmt_probe_free( session_stat->apps.web );
#endif

	mmt_probe_free( session_stat );
}

int session_report_callback_on_receiving_packet(const ipacket_t * ipacket, session_stat_t * session_stat){

#ifndef SIMPLE_REPORT
	//only for packet based on TCP
	if (session_stat != NULL && session_stat->dtt_seen == false ){
		struct timeval ts = get_session_rtt(ipacket->session);
		//this will exclude all the protocols except TCP
		uint64_t usec = u_second( &ts );
		if( usec != 0){
			uint8_t direction = get_session_last_packet_direction(ipacket->session);
			//The download direction is opposite to set_up_direction, the download direction is from server to client
			if( direction != get_session_setup_direction(ipacket->session)){
				struct timeval t1;
				t1 = get_session_last_data_packet_time_by_direction(ipacket->session, direction );

				if (t1.tv_sec > 0
						//&& u_second_diff(&ipacket->p_hdr->ts, & session->start_time) > usec
						){
					session_stat->dtt_seen = true;
					session_stat->dtt_start_time = ipacket->p_hdr->ts;
				}
			}
		}
	}
#endif

	return 0;
}


void session_report_do_report(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context){
	_print_ip_session_report ( dpi_session, session_stat, context );
}

/**
 * This function registers the required attributes for a flow (session)
 */
static inline void
	_register_protocols( mmt_handler_t *mmt_handler ) {
	int ret = 1;
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_SRC_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_DEST_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_UDP, UDP_SRC_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_UDP, UDP_DEST_PORT);

	ret &= register_extraction_attribute(mmt_handler, PROTO_ETHERNET, ETH_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_ETHERNET, ETH_SRC);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_SRC);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_PROTO_ID);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_SERVER_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_CLIENT_PORT);

	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_NEXT_PROTO);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SRC);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_DST);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_SERVER_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_IPV6, IP6_CLIENT_PORT);

	if(!ret) {
		//we need a sound error handling mechanism! Anyway, we should never get here :)
		log_write(LOG_ERR, "Error while initializing MMT handlers and extractions!");
	}
}

size_t get_session_web_handlers_to_register(const conditional_handler_t**);
size_t get_session_ssl_handlers_to_register( const conditional_handler_t **ret );
size_t get_session_rtp_handlers_to_register( const conditional_handler_t **ret );

bool session_report_register( mmt_handler_t *dpi_handler, session_report_conf_t *config ){
	if( ! config->is_enable )
		return false;

	//register basic protocols and their attributes for IP session statistic
	_register_protocols( dpi_handler );

	size_t size;
	const conditional_handler_t* handlers;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//register protocols and attributes for application statistic: WEB, FTP, RTP, SSL
	if( config->is_http ){
		size = get_session_web_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, NULL );
	}

	if( config->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, NULL );
	}

	if( config->is_rtp ){
		size = get_session_rtp_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, NULL );
	}
#endif

	return true;
}


bool session_report_unregister( mmt_handler_t *dpi_handler, session_report_conf_t *config ){
	if( ! config->is_enable )
		return false;

	size_t size;
	const conditional_handler_t* handlers;

#ifdef SIMPLE_REPORT
	//use simpler report version: this output is used by mmt-box
#else
	//register protocols and attributes for application statistic: WEB, FTP, RTP, SSL
	if( config->is_http ){
		size = get_session_web_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers);
	}

	if( config->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
	if( config->is_rtp ){
		size = get_session_rtp_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
#endif

	return true;
}
