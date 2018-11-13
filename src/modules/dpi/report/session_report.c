/*
 * session_report.c
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#define BEHAVIOUR_REPORT_ID 101

#include <arpa/inet.h>
#include "session_report.h"


#include "../../../lib/string_builder.h"
#include "../../../lib/log.h"
#include "../../../lib/inet.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

//functions implemented by session_report_xxx.c
int print_web_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_ssl_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_ftp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_rtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);
int print_gtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context);


static inline void _write_behaviour_report( file_output_t *output,
		int probe_id,
		const char *input_src,
		const struct timeval *timestamp,
		int proto_id,
		const char *ip_src,
		const char *ip_dst,
		uint64_t ul_volume,
		uint64_t dl_volume
		){

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( BEHAVIOUR_REPORT_ID ),
			__INT( probe_id ),
			__STR( input_src ),
			__TIME( timestamp ),
			__INT( proto_id ),
			__INT( ul_volume ),
			__INT( dl_volume ),
			__STR( ip_src ),
			__STR( ip_dst )
	);

	file_output_write( output, message );
}



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

	const proto_hierarchy_t * proto_hierarchy = get_session_protocol_hierarchy(dpi_session);
	int proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];

	uint64_t data_transfer_time = 0;
#ifdef QOS_MODULE
	// Data transfer time calculation
	if (session_stat->dtt_start_time.tv_sec > 0 ){
		struct timeval t1;
		//The download direction is opposite to set_up_direction,
		//  the download direction is from server to client
		if (get_session_setup_direction(dpi_session) == 1)
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 0);
		else
			t1 = get_session_last_data_packet_time_by_direction(dpi_session, 1);

		if( t1.tv_sec > 0 ){
			long v = u_second_diff( &t1, &session_stat->dtt_start_time );

			//v<0 if t1 is before session_stat->dtt_start_time
			//how come???

//			DEBUG("DTT: %lu", v);

			if( v >= 0 ){
				data_transfer_time =  v;
				session_stat->dtt_start_time = t1;
			}
//			else{
//				DEBUG( "DTT is too big" );
//			}
		}
	}
#endif

	char path_ul[128], path_dl[128];

	dpi_proto_hierarchy_ids_to_str(
			get_session_proto_path_direction( dpi_session, 1 ),
			path_ul, sizeof( path_ul) );

	dpi_proto_hierarchy_ids_to_str(
			get_session_proto_path_direction( dpi_session, 0 ),
			path_dl, sizeof( path_dl ));

	uint64_t total_active_sessions = get_active_session_count( context->dpi_handler );

#ifdef QOS_MODULE
	struct timeval rtt_time = get_session_rtt(dpi_session);
	uint64_t rtt_at_handshake = u_second( &rtt_time );
#endif

	//DEBUG("handshake: %lu", rtt_at_handshake );
	uint64_t total_retrans = get_session_retransmission_count( dpi_session );

	struct timeval start_time = get_session_init_time(dpi_session);

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
		__INT( context->stat_periods_index),
		__INT( proto_id),
		__STR( path_ul),
		__STR( path_dl),
		__INT( total_active_sessions),
		__INT( total_volumes - (session_stat->volumes.upload + session_stat->volumes.download)),
		__INT( total_payload - (session_stat->payload.upload + session_stat->payload.download)),
		__INT( total_packets - (session_stat->packets.upload + session_stat->packets.download)),
		__INT( ul_volumes - session_stat->volumes.upload),
		__INT( ul_payload - session_stat->payload.upload),
		__INT( ul_packets - session_stat->packets.upload),
		__INT( dl_volumes - session_stat->volumes.download),
		__INT( dl_payload - session_stat->payload.download),
		__INT( dl_packets - session_stat->packets.download),
		__TIME( &start_time ),
		__STR( session_stat->ip_src.ip_string ),
		__STR( session_stat->ip_dst.ip_string ),
		__MAC( session_stat->mac_src ),
		__MAC( session_stat->mac_dst),
		__INT( get_session_id( dpi_session ) ),
		__INT( session_stat->port_dst ),
		__INT( session_stat->port_src),
		__INT( context->worker_index),
	#ifdef QOS_MODULE
		__INT( ((session_stat->rtt_at_handshake == 0)? rtt_at_handshake : 0)),
		__INT( session_stat->rtt_min_usec[1]),
		__INT( session_stat->rtt_min_usec[0]),
		__INT( session_stat->rtt_max_usec[1]),
		__INT( session_stat->rtt_max_usec[0]),
		__INT( session_stat->rtt_avg_usec[1]),
		__INT( session_stat->rtt_avg_usec[0]),
	#else
		__ARR( "0,0,0,0,0,0,0" ), //string without closing by quotes
	#endif
		__INT(    data_transfer_time ),
		__INT(    (total_retrans - session_stat->retransmission_count)),
		__INT(    session_stat->app_type),
		__INT(    get_application_class_by_protocol_id( proto_id )),
		__INT(    session_stat->content_class)
	);

	if( session_stat->app_type ){
		message[ valid ++ ] = ','; //a comma separator between basic report part and ftp report part

		//get_application_class_by_protocol_id( session->proto_id )
		//append stats of application beyond IP
		switch( session_stat->app_type ){
		case SESSION_STAT_TYPE_APP_IP:
			break;
		case SESSION_STAT_TYPE_APP_WEB:
			valid += print_web_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_SSL:
			valid += print_ssl_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_FTP:
			valid += print_ftp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_RTP:
			valid += print_rtp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		case SESSION_STAT_TYPE_APP_GTP:
			valid += print_gtp_report( &message[ valid ], MAX_LENGTH_REPORT_MESSAGE - valid,
					dpi_session, session_stat, context );
			break;
		default:
			DEBUG("Does not support stat_type = %d", session_stat->app_type );
		}
		message[ valid ] = '\0';
	}

	struct timeval timestamp = get_session_last_activity_time( dpi_session );

	output_write_report( context->output,
			context->probe_config->reports.session->output_channels,
			SESSION_REPORT_TYPE,
			//timestamp is the one of the last packet in the session
			& timestamp,
			message );

	//if output for behaviour analysis is enabled
	if( context->behaviour_output != NULL )
		_write_behaviour_report(context->behaviour_output,
				context->probe_config->probe_id,
				context->probe_config->input->input_source,
				&timestamp,
				proto_id,
				session_stat->ip_src.ip_string,
				session_stat->ip_dst.ip_string,
				ul_volumes - session_stat->volumes.upload,
				dl_volumes - session_stat->volumes.download
		);


	//remember the current statistics
	session_stat->retransmission_count = total_retrans;

	session_stat->volumes.upload = ul_volumes;
	session_stat->volumes.download = dl_volumes;

	session_stat->payload.upload = ul_payload;
	session_stat->payload.download = dl_payload;

	session_stat->packets.upload = ul_packets;
	session_stat->packets.download = dl_packets;

#ifdef QOS_MODULE
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
#endif
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
	int proto_id = 0;
	if( likely( proto_hierarchy->len > 0 ))
		proto_id = proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];

	char app_path[128];

	dpi_proto_hierarchy_ids_to_str(
			proto_hierarchy,
			app_path, sizeof( app_path) );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( context->stat_periods_index ),
			__INT( proto_id ),
			__STR( app_path ),

			__INT( ul_volumes - session->volumes.upload ),
			__INT( dl_volumes - session->volumes.download ),

			__STR( session->ip_src.ip_string ),
			__STR( session->ip_dst.ip_string ),

			__MAC( session->mac_src ),
			__MAC( session->mac_dst ),

			__INT( session->port_dst ),
			__INT( session->port_src )
	);

	output_write_report( context->output,
				context->probe_config->reports.session->output_channels,
				SESSION_REPORT_TYPE,
				//timestamp is the one of the last packet in the session
				& last_activity_time,
				message );



	//if output for behaviour analysis is enabled
	if( context->behaviour_output != NULL )
		_write_behaviour_report(context->behaviour_output,
				context->probe_config->probe_id,
				context->probe_config->input->input_source,
				&last_activity_time,
				proto_id,
				session->ip_src.ip_string,
				session->ip_dst.ip_string,
				ul_volumes - session->volumes.upload,
				dl_volumes - session->volumes.download
		);

	//remember the current ul and dl data volumes
	session->volumes.upload   = ul_volumes;
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


session_stat_t *session_report_callback_on_starting_session ( const ipacket_t * ipacket, dpi_context_t *context ){
	mmt_session_t * dpi_session = ipacket->session;
	if( unlikely( dpi_session == NULL)){
		DEBUG("session of packet %lu must not be NULL", ipacket->packet_id );
		return NULL;
	}

	session_stat_t *session_stat = mmt_alloc_and_init_zero( sizeof (session_stat_t));

#ifndef SIMPLE_REPORT
	session_stat->app_type    = SESSION_STAT_TYPE_APP_IP;
#endif
	//the index in the protocol hierarchy of the protocol \session belongs to
	const uint32_t proto_session_index  = get_session_protocol_index( dpi_session );
	// Flow extraction
	const uint32_t proto_session_id = get_protocol_id_at_index(ipacket, proto_session_index);

	//must be either PROTO_IP or PROTO_IPV6
	if( unlikely( proto_session_id != PROTO_IP && proto_session_id != PROTO_IPV6 )){
		DEBUG("session of packet %lu is not on top of IP nor IPv6, but %d", ipacket->packet_id, proto_session_id );
		return NULL;
	}

	const bool is_session_over_ipv4 = (proto_session_id == PROTO_IP);


	uint8_t *src = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_SRC);
	uint8_t *dst = (uint8_t *) get_attribute_extracted_data(ipacket, PROTO_ETHERNET, ETH_DST);

	if (likely( src ))
		assign_6bytes( session_stat->mac_src, src );
	if (likely( dst ))
		assign_6bytes( session_stat->mac_dst, dst );

	//IPV4
	if (likely( is_session_over_ipv4 )) {

		uint32_t * ip_src = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_SRC, proto_session_index);
		uint32_t * ip_dst = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_DST, proto_session_index);

		if (likely( ip_src ))
			session_stat->ip_src.ipv4 = *ip_src;

		if (likely( ip_dst ))
			session_stat->ip_dst.ipv4 = (*ip_dst);


		inet_ntop4(session_stat->ip_src.ipv4, session_stat->ip_src.ip_string);
		inet_ntop4(session_stat->ip_dst.ipv4, session_stat->ip_dst.ip_string);

		uint16_t * cport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_CLIENT_PORT, proto_session_index);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_SERVER_PORT, proto_session_index);
		if( likely( cport ))
			session_stat->port_src = *cport;

		if( likely( dport ))
			session_stat->port_dst = *dport;

	} else {
		void * ipv6_src = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_SRC, proto_session_index);
		void * ipv6_dst = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_DST, proto_session_index);
		if (likely( ipv6_src ))
			assign_16bytes( &session_stat->ip_src.ipv6, ipv6_src);
		if (likely( ipv6_dst ))
			assign_16bytes(&session_stat->ip_dst.ipv6, ipv6_dst);

		inet_ntop(AF_INET6, (void *) &session_stat->ip_src.ipv6, session_stat->ip_src.ip_string, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &session_stat->ip_dst.ipv6, session_stat->ip_dst.ip_string, INET6_ADDRSTRLEN);


		uint16_t * cport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_CLIENT_PORT, proto_session_index);
		uint16_t * dport = (uint16_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_SERVER_PORT, proto_session_index);
		if (likely( cport ))
			session_stat->port_src = *cport;
		if (likely( dport ))
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

#ifdef QOS_MODULE
	//dtt_start_time: store the timestamp of the first data packet (the one is just after 3-way handshake) in a TCP session
	//only for packet based on TCP
	if (session_stat != NULL && session_stat->dtt_start_time.tv_sec == 0 ){
		struct timeval ts = get_session_rtt(ipacket->session);
		//this will exclude all the protocols except TCP
		uint64_t usec = u_second( &ts );
		//must have finished RTT
		if( usec != 0){
			uint8_t direction = get_session_last_packet_direction(ipacket->session);

			//The download direction is opposite to setup_direction,
			//  the download direction is from server to client
			if( direction != get_session_setup_direction(ipacket->session)){

				//moment the session was initialized
				struct timeval init_time_of_session = get_session_init_time( ipacket->session);

				//the packet is outside of handshake process
				if ( u_second_diff(&ipacket->p_hdr->ts, &init_time_of_session ) > usec )
					session_stat->dtt_start_time = ipacket->p_hdr->ts;
			}
		}
	}
#endif

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

size_t get_session_web_handlers_to_register( const conditional_handler_t ** );
size_t get_session_ssl_handlers_to_register( const conditional_handler_t ** );
size_t get_session_rtp_handlers_to_register( const conditional_handler_t ** );
size_t get_session_gtp_handlers_to_register( const conditional_handler_t ** );

bool session_report_register( mmt_handler_t *dpi_handler, session_report_conf_t *config, dpi_context_t *dpi_context ){
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
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}

	if( config->is_ssl ){
		size = get_session_ssl_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}

	if( config->is_rtp ){
		size = get_session_rtp_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
	}
	if( config->is_gtp ){
		size = get_session_gtp_handlers_to_register( &handlers );
		dpi_register_conditional_handler( dpi_handler, size, handlers, dpi_context );
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
	if( config->is_gtp ){
		size = get_session_gtp_handlers_to_register( &handlers );
		dpi_unregister_conditional_handler( dpi_handler, size, handlers );
	}
#endif

	return true;
}
