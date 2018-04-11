/*
 * session_report.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#include "header.h"

#include <arpa/inet.h>

int print_web_report(char *message, size_t message_size, packet_session_t *session, dpi_context_t *context);

//This callback is called by DPI periodically
static inline void _print_ip_session_report (const mmt_session_t * dpi_session, void *user_args){
	packet_session_t * session = (packet_session_t *) get_user_session_context(dpi_session);
	if( unlikely( session == NULL ))
		return;

	if( unlikely( is_micro_flow( dpi_session )))
		return;

	dpi_context_t *context = (dpi_context_t *)user_args;
	if( unlikely( context == NULL ))
		return;

	uint64_t total_volumes = get_session_data_cap_volume(dpi_session);
	if( unlikely( total_volumes == 0 ))
		return;

	uint64_t total_payload = get_session_byte_count(dpi_session),
			total_packets = get_session_packet_cap_count(dpi_session);

	uint64_t ul_volumes = get_session_ul_cap_byte_count(dpi_session),
			ul_payload = get_session_ul_data_byte_count(dpi_session),
			ul_packets = get_session_ul_cap_packet_count(dpi_session);

	uint64_t dl_volumes = get_session_dl_cap_byte_count(dpi_session),
			dl_payload = get_session_dl_data_byte_count(dpi_session),
			dl_packets = get_session_dl_cap_packet_count(dpi_session);

	uint64_t report_number;
	struct timeval last_activity_time = get_session_last_activity_time(dpi_session);

	//To check whether the session activity occurs between the reporting time interval
	if (u_second_diff( &last_activity_time, &session->data_stat.last_activity_time ) == 0)
		return;

	// check the condition if in the last interval there was a protocol activity or not
	//if (get_session_byte_count(session) - temp_session->stat.total_byte_count == 0)return;

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];
	session->data_stat.last_activity_time =  last_activity_time;
	session->data_stat.start_time = get_session_init_time(dpi_session);

	uint64_t data_transfer_time = 0;
	// Data transfer time calculation
	if (session->dtt_seen ){
		struct timeval t1;
		//The download direction is opposite to set_up_direction, the download direction is from server to client
		if (get_session_setup_direction(dpi_session) == 1)
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 0);
		else
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 1);

		data_transfer_time      =  u_second_diff(&t1, &session->dtt_start_time);
		session->dtt_start_time = t1;
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

			total_volumes - session->data_stat.total_volumes,
			total_payload - session->data_stat.total_payload,
			total_packets - session->data_stat.total_packets,

			ul_volumes - session->data_stat.volumes.upload,
			ul_payload - session->data_stat.payload.upload,
			ul_packets - session->data_stat.packets.upload,

			dl_volumes - session->data_stat.volumes.download,
			dl_payload - session->data_stat.payload.download,
			dl_packets - session->data_stat.packets.download,

			session->data_stat.start_time.tv_sec, session->data_stat.start_time.tv_usec,
			session->ip_src.ip_string, session->ip_dst.ip_string,
			MAC_ELEMENT( session->mac_src ),//src_mac_pretty,
			MAC_ELEMENT( session->mac_dst ),//dst_mac_pretty,
			session ->session_id,
			session->port_dst, session->port_src,

			context->worker_index, //thread_id

			((session->rtt_at_handshake == 0)? rtt_at_handshake : 0),
			session->data_stat.rtt_min_usec[1],
			session->data_stat.rtt_min_usec[0],
			session->data_stat.rtt_max_usec[1],
			session->data_stat.rtt_max_usec[0],
			session->data_stat.rtt_avg_usec[1],
			session->data_stat.rtt_avg_usec[0],

			data_transfer_time,
			(total_retrans - session->data_stat.retransmission_count),

			session->app_type,

			get_application_class_by_protocol_id( proto_id ),
			session->content_class
	);

	//get_application_class_by_protocol_id( session->proto_id )
	//append stats of application beyond IP
	switch( session->app_type ){
	case SESSION_STAT_TYPE_APP_IP:
		break;
	case SESSION_STAT_TYPE_APP_WEB:
		valid += print_web_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
				session, context );
		break;
	case SESSION_REPORT_SSL_TYPE:
		break;
	case SESSION_REPORT_FTP_TYPE:
		break;
	case SESSION_REPORT_RTP_TYPE:
		break;
	default:
		DEBUG("Does not support stat_type = %d", session->app_type );
	}
//	if (session->app_format_id == MMT_WEB_REPORT_FORMAT && probe_context->web_enable == 1)
//		print_initial_web_report(dpi_session, session, message,valid);
//	else if (session->app_format_id == MMT_RTP_REPORT_FORMAT && probe_context->rtp_enable == 1)
//		print_initial_rtp_report(dpi_session, session, message,valid);
//	else if (session->app_format_id == MMT_SSL_REPORT_FORMAT && session->stat.touched == 0 && probe_context->ssl_enable == 1)
//		print_initial_ssl_report(dpi_session, session, message, valid);
//	else if (session->app_format_id == MMT_FTP_REPORT_FORMAT && probe_context->ftp_enable == 1)
//		print_initial_ftp_report(dpi_session, session, message, valid);
//	else if(session->stat.touched == 0){
//		sslindex = get_protocol_index_from_session(proto_hierarchy, PROTO_SSL);
//		if (sslindex != -1 && probe_context->ssl_enable == 1 ){
//			session->app_format_id = MMT_SSL_REPORT_FORMAT;
//			print_initial_ssl_report(dpi_session, session, message, valid);
//		}else print_initial_default_report(dpi_session, session, message, valid);
//	}


	output_write_report( context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			&session->data_stat.last_activity_time,
			message );


	session->data_stat.retransmission_count = total_retrans;

	session->data_stat.total_volumes = total_volumes;
	session->data_stat.total_payload = total_payload;
	session->data_stat.total_packets = total_packets;

	session->data_stat.volumes.upload = ul_volumes;
	session->data_stat.volumes.download = dl_volumes;

	session->data_stat.payload.upload = ul_payload;
	session->data_stat.payload.download = dl_payload;

	session->data_stat.packets.upload = ul_packets;
	session->data_stat.packets.download = dl_packets;

	session->data_stat.rtt_min_usec[1] = 0;
	session->data_stat.rtt_min_usec[0] = 0;
	session->data_stat.rtt_max_usec[1] = 0;
	session->data_stat.rtt_max_usec[0] = 0;
	session->data_stat.rtt_avg_usec[0] = 0;
	session->data_stat.rtt_avg_usec[1] = 0;
	session->data_stat.rtt_counter[0]  = 0;
	session->data_stat.rtt_counter[1]  = 0;
	session->data_stat.sum_rtt[0]      = 0;
	session->data_stat.sum_rtt[1]      = 0;
	session->rtt_at_handshake     = rtt_at_handshake;
}
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


static inline packet_session_t *_create_session (const ipacket_t * ipacket, dpi_context_t *context){
	mmt_session_t * dpi_session = ipacket->session;
	if(dpi_session == NULL) return NULL;

	packet_session_t *session = mmt_alloc(sizeof (packet_session_t));

	memset(session, 0, sizeof (packet_session_t));

	session->dpi_session = dpi_session;
	session->context     = context;
	session->session_id  = get_session_id( dpi_session );
	session->app_type    = SESSION_STAT_TYPE_APP_IP;

	// Flow extraction
	int ip_index = get_protocol_index_by_id(ipacket, PROTO_IP);

	uint8_t *src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
	uint8_t *dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);

	if (src)
		//memcpy(session->mac_src, src, 6);
		assign_6bytes( session->mac_src, src );
	if (dst)
		//memcpy(session->mac_dst, dst, 6);
		assign_6bytes( session->mac_dst, dst );

	//IPV4
	if (ip_index != -1) {

		uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SRC);
		uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_DST);

		if (ip_src)
			session->ip_src.ipv4 = (*ip_src);


		if (ip_dst)
			session->ip_dst.ipv4 = (*ip_dst);


		inet_ntop(AF_INET, (void *) &session->ip_src.ipv4, session->ip_src.ip_string, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &session->ip_dst.ipv4, session->ip_dst.ip_string, INET_ADDRSTRLEN);

		uint8_t *proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_PROTO_ID);
		if( likely( proto_id != NULL ))
			session->proto = *proto_id;

		session->ip_version = IPv4;
		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IP, IP_SERVER_PORT);
		if (cport)
			session->port_src = *cport;

		if (dport)
			session->port_dst = *dport;

	} else {
		void * ipv6_src = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SRC);
		void * ipv6_dst = (void *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_DST);
		if (ipv6_src) {
			memcpy(&session->ip_src.ipv6, ipv6_src, 16);
		}
		if (ipv6_dst) {
			memcpy(&session->ip_dst.ipv6, ipv6_dst, 16);
		}

		inet_ntop(AF_INET6, (void *) &session->ip_src.ipv6, session->ip_src.ip_string, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &session->ip_dst.ipv6, session->ip_dst.ip_string, INET6_ADDRSTRLEN);


		uint8_t * proto_id = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_NEXT_PROTO);
		if (proto_id != NULL) {
			session->proto = *proto_id;
		} else {
			session->proto = 0;
		}
		session->ip_version = IPv6;
		uint16_t * cport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_CLIENT_PORT);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data(ipacket, PROTO_IPV6, IP6_SERVER_PORT);
		if (cport)
			session->port_src = *cport;
		if (dport)
			session->port_dst = *dport;
	}

	session->is_flow_extracted = 1;

    //    printf ("set session\n");
	set_user_session_context(dpi_session, session);
	return session;
}


/* This function is called by mmt-dpi for each session time-out (expiry).
 * It provides the expired session information and frees the memory allocated.
 * */
static void _expired_session_callback(const mmt_session_t * expired_session, void * args) {
	//	debug("classification_expiry_session : %lu",get_session_id(expired_session));
	packet_session_t * session = get_user_session_context(expired_session);
	if (session == NULL)
		return;

	dpi_context_t *context = (dpi_context_t *) args;

	if (is_micro_flow( expired_session )) {
//		microsessions_stats_t * mf_stats = &th->iprobe.mf_stats[get_session_protocol_hierarchy(expired_session)->proto_path[(get_session_protocol_hierarchy(expired_session)->len <= 16)?(get_session_protocol_hierarchy(expired_session)->len - 1):(16 - 1)]];

//		update_microflows_stats(mf_stats, expired_session);
//		if (is_microflow_stats_reportable(mf_stats)) {
//			report_microflows_stats(mf_stats, args);
//		}
		return;
	}

	_print_ip_session_report ( expired_session, context );

	//release memory being allocated for application stat (web, ftp, rtp, ssl)
	switch( session->app_type ){
	default:
		break;
	}

	mmt_probe_free( session->apps.web );

	mmt_probe_free(session);
}

static int _packet_handler_for_session(const ipacket_t * ipacket, void * args) {
	dpi_context_t *context = (dpi_context_t *)args;

	packet_session_t *session = (packet_session_t *) get_user_session_context_from_packet(ipacket);

	if( unlikely( ipacket->session != NULL && session == NULL))
		session = _create_session (ipacket, context);

	//only for packet based on TCP
	if (session != NULL && session->dtt_seen == false ){
		struct timeval ts = get_session_rtt(ipacket->session);
		//this will exclude all the protocols except TCP
		uint64_t usec = u_second( &ts );
		if( usec != 0){
			uint8_t direction = get_session_last_packet_direction(ipacket->session);
			//The download direction is opposite to set_up_direction, the download direction is from server to client
			if( direction != get_session_setup_direction(ipacket->session)){
				struct timeval t1;
				t1 = get_session_last_data_packet_time_by_direction(ipacket->session, direction );

				if (t1.tv_sec > 0 &&
						u_second_diff(&ipacket->p_hdr->ts, & session->data_stat.start_time) > usec){
					session->dtt_seen = true;
					session->dtt_start_time = ipacket->p_hdr->ts;
				}
			}
		}
	}

	return 0;
}



static void _flow_nb_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	packet_session_t *session = (packet_session_t *) get_user_session_context_from_packet(ipacket);

	if( session == NULL )
		_create_session (ipacket, user_args);
}

/**
 * This function registers the required attributes for a flow (session)
 */
static inline
void _register_protocols( dpi_context_t *context ) {
	mmt_handler_t *mmt_handler = context->dpi_handler;
	int ret = 1;
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_SRC_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_DEST_PORT);
	ret &= register_extraction_attribute(mmt_handler, PROTO_TCP, TCP_RTT);
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

	if( context->probe_config->is_enable_ip_fragementation ){
		ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_FRAG_PACKET_COUNT);
		ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_FRAG_DATA_VOLUME);
		ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_DF_PACKET_COUNT);
		ret &= register_extraction_attribute(mmt_handler, PROTO_IP, IP_DF_DATA_VOLUME);
	}

	ret &= register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION, _flow_nb_handle, NULL, (void *)context);

//	ret &= register_attribute_handler(mmt_handler, PROTO_IPV6, PROTO_SESSION, flow_nb_handle, NULL, (void *)context);
//	ret &= register_attribute_handler(mmt_handler, PROTO_IP, IP_RTT, ip_rtt_handler, NULL, (void *)context);
//	ret &=register_attribute_handler(mmt_handler, PROTO_TCP,TCP_CONN_CLOSED, tcp_closed_handler, NULL, (void *)context);

	/*if(probe_context->ftp_enable == 1){
		register_ftp_attributes(mmt_handler);
	}*/

	if(!ret) {
		//we need a sound error handling mechanism! Anyway, we should never get here :)
		log_write(LOG_ERR, "Error while initializing MMT handlers and extractions!");
	}
}


/* This function registers attributes and attribute handlers for different condition_reports (if enabled in a configuration file).
 * */
static inline int _register_conditional_handler( size_t count,  const conditional_handler_t *handlers, dpi_context_t *context) {
	int i, ret = 0;
	const conditional_handler_t *handler;
	mmt_handler_t *dpi_handler = context->dpi_handler;

	for( i=0; i<count; i++ ){
		handler = &handlers[i];

		//register without handler function
		if( handler->handler == NULL ){
			if( ! register_extraction_attribute( dpi_handler, handler->proto_id, handler->att_id) )
				log_write( LOG_WARNING, "Cannot register attribute %u.%u",
						handler->proto_id, handler->att_id	);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler,  handler->proto_id, handler->att_id, handler->handler, NULL, context ) )
				log_write( LOG_ERR, "Cannot register handler for %u.%u",
						handler->proto_id, handler->att_id );
			else
				ret ++;
		}
	}
	return ret;
}

size_t get_session_web_handlers_to_register(const conditional_handler_t**);
size_t get_session_ssl_handlers_to_register( const conditional_handler_t **ret );

bool session_report_register( dpi_context_t *context ){
	if( ! context->probe_config->reports.session->is_enable )
		return false;

	//this handler is used only for handling session
	int ret = register_packet_handler( context->dpi_handler, 6, _packet_handler_for_session, context );

	if( ! ret)
		ABORT( "Cannot register packet handler for session processing" );

	//register basic protocols and their attributes for IP session statistic
	_register_protocols( context );

	size_t size;
	const conditional_handler_t* handlers;

	//register protocols and attributes for application statistic: WEB, FTP, RTP, SSL
	if( context->probe_config->reports.session->is_http ){
		size = get_session_web_handlers_to_register( &handlers );
		_register_conditional_handler( size, handlers, context );
	}
	if( context->probe_config->reports.session->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		_register_conditional_handler( size, handlers, context );
	}



	register_session_timer_handler(context->dpi_handler,   _print_ip_session_report, context);

	register_session_timeout_handler(context->dpi_handler, _expired_session_callback, context);

	return true;
}
