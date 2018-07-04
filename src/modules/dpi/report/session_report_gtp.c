/*
 * session_report_gtp.c
 *
 *  Created on: Jun 22, 2018
 *          by: Huu Nghia Nguyen
 */


#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "session_report.h"
//we take the second IP in a protocol hierarchy
#define IP_ENCAP_INDEX_AFTER_GTP 1

//Number of TEIDs may appear in a TCP/IP session
#define MAX_NB_TEID 2

struct session_gtp_stat_struct{
	uint32_t teids[ MAX_NB_TEID ];
	uint8_t ip_version;
	mmt_ipv4_ipv6_t ip_src;
	mmt_ipv4_ipv6_t ip_dst;
};

//session is based on IP after GTP, not on IP after ETHERNET
//this ensures GTP is after IP session
#define _is_session_based_on_ip_after_gtp( ipacket  )\
	(ipacket->session && get_protocol_index_by_id(ipacket, PROTO_GTP) + 1 ==  get_session_protocol_index( ipacket->session ))

static inline session_gtp_stat_t *_get_gtp_session_data( const ipacket_t *ipacket, bool create_if_need ){
	int i;

	//must have a session
	if(ipacket->session == NULL)
		return NULL;

	//the session must be initialized by Probe (in function flow_nb_handle - processing.c)
	session_stat_t *temp_session = session_report_get_session_stat(ipacket);
	if(temp_session == NULL )
		return NULL;

	session_gtp_stat_t *gtp_data = NULL;
	//if GTP data is not initialized
	if( temp_session->apps.gtp == NULL && create_if_need ){
		gtp_data = (session_gtp_stat_t *) malloc( sizeof( session_gtp_stat_t ));
		memset(gtp_data, '\0', sizeof (session_gtp_stat_t));

		temp_session->app_type = SESSION_STAT_TYPE_APP_GTP;
		temp_session->apps.gtp = gtp_data;
	}
	else
		gtp_data = temp_session->apps.gtp;

	return gtp_data;
}

/**
 * Update IP src and DST
 * @param gtp_data
 * @param ipacket
 */
static inline void _gtp_update_ip( session_gtp_stat_t *gtp_data, const ipacket_t *ipacket ){
	//ip was extracted
	if( gtp_data->ip_version != 0 ){
		//what happen when IP is changed
		return;
	}

	//has IPv4 in protocol hierarchy ???
	const uint32_t * ipv4_src = get_attribute_extracted_data_encap_index( ipacket, PROTO_IP, IP_SRC, IP_ENCAP_INDEX_AFTER_GTP );

	//IPv4
	if ( ipv4_src != NULL ) {
		gtp_data->ip_version = 4;
		gtp_data->ip_src.ipv4 = *(uint32_t *) ipv4_src;
		gtp_data->ip_dst.ipv4 = *(uint32_t *) get_attribute_extracted_data_encap_index( ipacket, PROTO_IP, IP_DST, IP_ENCAP_INDEX_AFTER_GTP );
	}else{
		gtp_data->ip_version = 6;
		memcpy(&gtp_data->ip_src.ipv6,
				get_attribute_extracted_data_encap_index( ipacket, PROTO_IPV6, IP6_SRC, IP_ENCAP_INDEX_AFTER_GTP ),
				16);
		memcpy( gtp_data->ip_dst.ipv6,
				get_attribute_extracted_data_encap_index( ipacket, PROTO_IPV6, IP6_DST, IP_ENCAP_INDEX_AFTER_GTP ),
				16);
	}
}

/**
 * Append teid in an IP session to collect all teid that appears in the packets of the session
 * @param gtp_data
 * @param ipacket
 */
static inline void _gtp_update_teid( session_gtp_stat_t *gtp_data, const ipacket_t *ipacket ){
	int i;
	const uint32_t *teid = ( uint32_t *) get_attribute_extracted_data( ipacket, PROTO_GTP, GTP_TEID );
	//We has no TEID as we are processing IP that is before GTP in the hierarchy
	//=> so we skip this IP session
	if( teid == NULL )
		return;

	//save all TEID appear in the session
	for( i=0; i<MAX_NB_TEID; i++ )
		//existing
		if( gtp_data->teids[i] == *teid )
			break;
		//add to an empty position
		else if( gtp_data->teids[i] == 0 ){
			//TODO: what happen when TEID is changed
			gtp_data->teids[i] = *teid;
			break;
		}

	if( i== MAX_NB_TEID ){
		log_write( LOG_WARNING, "More than %d TEIDs have been found on a session of packet having id = %lu\n", MAX_NB_TEID, ipacket->packet_id);
	}
}

//use this callback to process gtp.teid as gtp.teid is known before creating the IP session (as GTP.IP)
static void _gtp_ip_src_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	//the session must be beyond IP over GTP
	if( ! _is_session_based_on_ip_after_gtp(ipacket) )
		return;

	session_gtp_stat_t *gtp_data = _get_gtp_session_data(ipacket, true);

	_gtp_update_ip( gtp_data, ipacket );

	_gtp_update_teid( gtp_data, ipacket );
}

//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_gtp_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
			{.proto_id = PROTO_GTP, .att_id = GTP_TEID, .handler = NULL},
			{.proto_id = PROTO_IP,  .att_id = IP_SRC,   .handler = _gtp_ip_src_handle},
	};
	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}



/* This function is for reporting gtp session statistics*/
int print_gtp_report(char *message, size_t message_size, const mmt_session_t * dpi_session, session_stat_t *session_stat, const dpi_context_t *context){
	session_gtp_stat_t *gtp = session_stat->apps.gtp;

	//does not concern
	if( unlikely( gtp == NULL || session_stat->app_type != SESSION_STAT_TYPE_APP_GTP ))
		return 0;

	char ip_src_str[46];
	char ip_dst_str[46];
	if (gtp->ip_version == 4) {
		inet_ntop(AF_INET, (void *) &gtp->ip_src.ipv4, ip_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, (void *) &gtp->ip_dst.ipv4, ip_dst_str, INET_ADDRSTRLEN);
	} else if(gtp->ip_version == 6) {
		inet_ntop(AF_INET6, (void *) &gtp->ip_src.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &gtp->ip_dst.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
	}else{
		ip_src_str[0] = '\0';
		ip_dst_str[0] = '\0';
	}


	int  ret = 0;
	STRING_BUILDER_WITH_SEPARATOR( ret, message, message_size, ",",
			__STR( ip_src_str ),
			__STR( ip_dst_str ),
			__INT( gtp->teids[0] ),
			__INT( gtp->teids[1] )
	);


    return ret;
}
