/*
 * header.h
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_HEADER_H_
#define SRC_MODULES_DPI_HEADER_H_


#ifndef STAT_REPORT
#define STAT_REPORT
#endif

#include "../dpi.h"
#include "../dpi_tool.h"
#include "tcp_rtt.h"

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>

#define PRETTY_MAC_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ELEMENT( x )  x[0], x[1], x[2], x[3], x[4], x[5]

#define IPv4 4
#define IPv6 6

#define has_string( x )   ( x[0] != '\0' )
#define reset_string( x )   x[0]  = '\0'
#define reset_timeval(x)    x.tv_sec = x.tv_usec = 0
typedef enum{
	SESSION_STAT_TYPE_APP_IP  = 0,
	SESSION_STAT_TYPE_APP_WEB = 1,
	SESSION_STAT_TYPE_APP_SSL = 2,
	SESSION_STAT_TYPE_APP_RTP = 3,
	SESSION_STAT_TYPE_APP_FTP = 4,
	SESSION_STAT_TYPE_APP_GTP = 5
}session_stat_type_t;

enum{
	DIRECTION_UPLOAD   = 0,
	DIRECTION_DOWNLOAD = 1
};

typedef struct mmt_ipv4_ipv6_struct {
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	};
	char ip_string[INET6_ADDRSTRLEN];
} mmt_ipv4_ipv6_t;

typedef struct flow_stat_data_struct{
	uint64_t upload;
	uint64_t download;
}flow_stat_data_t;

#define reset_flow_stat_data( x ) x.upload = x.download = 0

typedef struct session_web_stat_struct session_web_stat_t;
typedef struct session_ftp_stat_struct session_ftp_stat_t;
typedef struct session_rtp_stat_struct session_rtp_stat_t;
typedef struct session_ssl_stat_struct session_ssl_stat_t;
typedef struct session_gtp_stat_struct session_gtp_stat_t;

typedef struct session_stat_struct {
	mmt_ipv4_ipv6_t ip_src;
	mmt_ipv4_ipv6_t ip_dst;
	uint16_t port_src;
	uint16_t port_dst;

	uint8_t  mac_src[6];
	uint8_t  mac_dst[6];

	flow_stat_data_t volumes;

//we don't need these parameters in simple version for MMT-BOX
#ifndef SIMPLE_REPORT
	flow_stat_data_t payload;
	flow_stat_data_t packets;

	uint16_t content_class;

	//sub statistic (e.g., HTTP) beyond main stat (IP)
	session_stat_type_t app_type;
	union{
		session_web_stat_t *web;
		session_ftp_stat_t *ftp;
		session_rtp_stat_t *rtp;
		session_ssl_stat_t *ssl;
		session_gtp_stat_t *gtp;
	}apps;


#ifdef QOS_MODULE
	struct{
		uint64_t sum[2]; //total rtt in microsecond
		uint64_t max[2]; //max
		uint64_t min[2]; //min
		uint64_t counter[2]; //number of packets being calculated rtt => to calculate avg of rtt
	}rtt;

	tcp_rtt_t *tcp_rtt; /**< data structure to calculate rtt*/

	uint64_t retransmission[2];


	/*See ~/doc/img/tcp_qos_time.svg */
	//uint64_t handshake_time;      /**< Interval of 3-way handshake */
	//uint64_t app_response_time;   /**< Interval between the last packet in 3-way handshake, (ACK packet - when session established), and the first data packet being transmitted after that */
	//uint64_t data_transfer_time;  /**< Interval between the first data packet being transmitted and the current data packet at the sampling moment */

	struct timeval tcp_established_ts; /**< store the moment where tcp session is established */
	struct timeval latest_tcp_data_pkt_ts; /**< store the timestamp of the most recent data packet in the tcp session*/

	//handshake_time and app_response_time are reported only once
	//data_transfer_time is reported progressively
	uint8_t is_printed_handshake_time;
	uint8_t is_printed_app_response_time;

#endif


	bool is_classified;
#endif

} session_stat_t;


static inline session_stat_t *session_report_get_session_stat(const ipacket_t * ipacket){
	packet_session_t *session =
			(packet_session_t *) get_user_session_context_from_packet(ipacket);

	if( session == NULL )
		return NULL;

	return session->session_stat;
}

//This function must be called when starting a session
session_stat_t *session_report_callback_on_starting_session ( const ipacket_t * ipacket, dpi_context_t *context );

/**
 * This function must be called on each coming packet
 */
int session_report_callback_on_receiving_packet(const ipacket_t * ipacket, session_stat_t * session_stat, dpi_context_t *dpi_context );

/**
 * This function must be called when finishing a tcp session
 * @param dpi_session
 * @param session_stat
 * @param context
 */
void session_report_callback_on_ending_session(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context);

/**
 * This function must be called periodically to generate statistic reports of one TCP session
 * @param dpi_session
 * @param session_stat
 * @param context
 */
void session_report_do_report(const mmt_session_t * dpi_session, session_stat_t * session_stat, const dpi_context_t *context);

/*This function takes IPv6 address and finds whether this address belongs to a local network.
 *It returns 1 if the address belongs to a IPv6 local network
 */
static inline bool is_local_ipv6(char * a) {
	uint32_t *prefix = (uint32_t *)a;

	//TODO: fix this
	switch( *prefix ){
	case 1: //fe80
	case 2: //fec0
	case 3: //fc00
		return true;
	}

	return 0;
}

/*This function takes IPv4 address and finds whether this address belongs to a local network.
 *It returns 1 if the address belongs to a IPv4 local network
 */

static inline bool is_local_ipv4(uint32_t addr) {
	addr = (ntohl(addr) & 0xFF000000);

	switch( addr ){
	case 0x0A000000: //10.0.0.0
	case 0xC0000000: //192.0.0.0
	case 0xAC000000: //172.0.0.0
	case 0xA9000000: //169.0.0.0
		return true;
	default:
		return false;
	}
}

static inline const char* get_string_value( const char *value ){
	if( value[0] == '\0' )
		return "null";
	return value;
}

//header
bool session_report_register( mmt_handler_t *dpi_handler, session_report_conf_t *config, dpi_context_t *dpi_context );
bool session_report_unregister( mmt_handler_t *dpi_handler, session_report_conf_t *config );
#endif /* SRC_MODULES_DPI_HEADER_H_ */
