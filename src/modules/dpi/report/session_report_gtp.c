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

#include "../../../lib/inet.h"
#include "../../../lib/malloc_ext.h"
#include "session_report.h"

//Number of TEIDs may appear in a TCP/IP session
#define MAX_NB_TEID 6

struct session_gtp_stat_struct{
	uint32_t teids[ MAX_NB_TEID ];
	uint8_t ip_version;
	mmt_ipv4_ipv6_t ip_src;
	mmt_ipv4_ipv6_t ip_dst;
	uint8_t mac_src[6];
	uint8_t mac_dst[6];
};

/**
 * Index of GTP carrying the session of the packet, or -1 if the session is not just after GTP.
 * The session may be after the Ethernet of a GTP Ethernet PDU, e.g., ETH.IP.UDP.GTP.ETH.VLAN.IP
 */
static inline int _get_gtp_index_before_session( const ipacket_t *ipacket ){
	if( ipacket->session == NULL )
		return -1;
	int index = get_session_protocol_index( ipacket->session ) - 1;
	while( index > 0 ){
		switch( get_protocol_id_at_index( ipacket, index )){
		case PROTO_GTP:
			return index;
		case PROTO_ETHERNET:
		case PROTO_8021Q:
		case PROTO_8021AD:
			index --;
			break;
		default:
			return -1;
		}
	}
	return -1;
}

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
	//apps is a union: the session is used by another app report, e.g., HTTP
	if( temp_session->apps.gtp != NULL && temp_session->app_type != SESSION_STAT_TYPE_APP_GTP )
		return NULL;
	//if GTP data is not initialized
	if( temp_session->apps.gtp == NULL && create_if_need ){
		gtp_data = (session_gtp_stat_t *) mmt_alloc_and_init_zero( sizeof( session_gtp_stat_t ));

		temp_session->app_type = SESSION_STAT_TYPE_APP_GTP;
		temp_session->apps.gtp = gtp_data;
	}
	else
		gtp_data = temp_session->apps.gtp;

	return gtp_data;
}

/**
 * Update IP src and dst, MAC src and dst
 * This function get the "outer" IP: the one carrying GTP,
 *  and the "outer" MAC: the Ethernet before this IP.
 * The information of IP after GTP has been extracted by session_report when a new session is created
 * @param gtp_data
 * @param ipacket
 * @param gtp_index index of GTP in the protocol hierarchy
 */
static inline void _gtp_update_ip( session_gtp_stat_t *gtp_data, const ipacket_t *ipacket, int gtp_index ){
	//ip was extracted
	if( gtp_data->ip_version != 0 ){
		//what happen when IP is changed
		return;
	}

	//the IP carrying GTP, e.g., the IPv6 of ETH.IPV6.UDP.GTP.IP
	int index = gtp_index - 1;
	while( index > 0 && get_protocol_id_at_index( ipacket, index ) != PROTO_IP
			&& get_protocol_id_at_index( ipacket, index ) != PROTO_IPV6 )
		index --;
	//the Ethernet before it
	int eth_index = index - 1;
	while( eth_index > 0 && get_protocol_id_at_index( ipacket, eth_index ) != PROTO_ETHERNET )
		eth_index --;

	const uint8_t *mac_src = get_attribute_extracted_data_at_index( ipacket, PROTO_ETHERNET, ETH_SRC, eth_index );
	const uint8_t *mac_dst = get_attribute_extracted_data_at_index( ipacket, PROTO_ETHERNET, ETH_DST, eth_index );
	if( mac_src )
		memcpy( gtp_data->mac_src, mac_src, 6 );
	if( mac_dst )
		memcpy( gtp_data->mac_dst, mac_dst, 6 );

	//IPv4
	if ( get_protocol_id_at_index( ipacket, index ) == PROTO_IP ) {
		const uint32_t *ip_src = get_attribute_extracted_data_at_index( ipacket, PROTO_IP, IP_SRC, index );
		const uint32_t *ip_dst = get_attribute_extracted_data_at_index( ipacket, PROTO_IP, IP_DST, index );
		if( ip_src == NULL || ip_dst == NULL )
			return;
		gtp_data->ip_version = 4;
		gtp_data->ip_src.ipv4 = *ip_src;
		gtp_data->ip_dst.ipv4 = *ip_dst;
	}else if( get_protocol_id_at_index( ipacket, index ) == PROTO_IPV6 ){
		const void *ip_src = get_attribute_extracted_data_at_index( ipacket, PROTO_IPV6, IP6_SRC, index );
		const void *ip_dst = get_attribute_extracted_data_at_index( ipacket, PROTO_IPV6, IP6_DST, index );
		if( ip_src == NULL || ip_dst == NULL )
			return;
		gtp_data->ip_version = 6;
		memcpy( gtp_data->ip_src.ipv6, ip_src, 16 );
		memcpy( gtp_data->ip_dst.ipv6, ip_dst, 16 );
	}
}

/**
 * Append teid in an IP session to collect all teid that appears in the packets of the session
 * @param gtp_data
 * @param ipacket
 */
static inline void _gtp_update_teid( session_gtp_stat_t *gtp_data, const ipacket_t *ipacket, int gtp_index ){
	int i;
	const uint32_t *teid = ( uint32_t *) get_attribute_extracted_data_at_index( ipacket, PROTO_GTP, GTP_TEID, gtp_index );
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

	if( unlikely( i== MAX_NB_TEID )){
		log_write( LOG_WARNING, "More than %d TEIDs have been found on a session of packet having id = %lu\n", MAX_NB_TEID, ipacket->packet_id);
	}
}

//use this callback to process gtp.teid as gtp.teid is known before creating the IP session (as GTP.IP)
static void _gtp_ip_src_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	//the session must be beyond IP over GTP
	int gtp_index = _get_gtp_index_before_session( ipacket );
	if( gtp_index < 0 )
		return;

	session_gtp_stat_t *gtp_data = _get_gtp_session_data(ipacket, true);
	if( gtp_data == NULL )
		return;

	_gtp_update_ip( gtp_data, ipacket, gtp_index );

	_gtp_update_teid( gtp_data, ipacket, gtp_index );
}

//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_gtp_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
			{.proto_id = PROTO_GTP, .att_id = GTP_TEID, .handler = NULL},
			{.proto_id = PROTO_IP,  .att_id = IP_SRC,   .handler = _gtp_ip_src_handle},
			{.proto_id = PROTO_IPV6,.att_id = IP6_SRC,  .handler = _gtp_ip_src_handle},
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

	char ip_src_str[INET6_ADDRSTRLEN];
	char ip_dst_str[INET6_ADDRSTRLEN];
	if (gtp->ip_version == 4) {
		inet_ntop4(gtp->ip_src.ipv4, ip_src_str);
		inet_ntop4(gtp->ip_dst.ipv4, ip_dst_str);
	} else if(gtp->ip_version == 6) {
		inet_ntop(AF_INET6, (void *) &gtp->ip_src.ipv6, ip_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, (void *) &gtp->ip_dst.ipv6, ip_dst_str, INET6_ADDRSTRLEN);
	}else{
		ip_src_str[0] = '\0';
		ip_dst_str[0] = '\0';
	}


	int  ret = 0;
	STRING_BUILDER( ret, message, message_size,
			__STR( ip_src_str ),
			__CHAR(','),
			__STR( ip_dst_str ),
			__CHAR(','),
			__CHAR('[') //open an array of TEIDs
	);

	//append the of TEIDs, surrounded by [ and ]
	int i;
	bool has_teid = false;
	for( i=0; i<MAX_NB_TEID; i++ ){
		//when a TEID is zero, no more after it
		if( gtp->teids[i] == 0 )
			break;

		//each TEID is separated by comma
		// do not add comma before the first TEID
		if( has_teid )
			message[ret ++] = ',';

		ret += append_number( &message[ret], message_size - ret, gtp->teids[i] );
		has_teid = true;
	}

	message[ret ++] = ']'; //close the array of TEIDs

	STRING_BUILDER( ret, message, message_size,
			__CHAR(','),
			__MAC( gtp->mac_src ),
			__CHAR(','),
			__MAC( gtp->mac_dst )
	);

	return ret;
}
