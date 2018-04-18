/*
 * header.h
 *
 *  Created on: Dec 28, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_HEADER_H_

#define SRC_MODULES_DPI_HEADER_H_

#include "../dpi.h"
#include "../dpi_tool.h"
#include "../../../lib/memory.h"

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>

#define PRETTY_MAC_FORMAT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_ELEMENT( x )  x[0], x[1], x[2], x[3], x[4], x[5]

#define IPv4 4
#define IPv6 6

#define has_string( x )   ( x[0] != '\0' )
#define reset_string( x ) ( x[0]  = '\0' )

typedef enum{
	SESSION_STAT_TYPE_APP_IP  = 0,
	SESSION_STAT_TYPE_APP_WEB = 1,
	SESSION_STAT_TYPE_APP_SSL = 2,
	SESSION_STAT_TYPE_APP_RTP = 3,
	SESSION_STAT_TYPE_APP_FTP = 4
}session_stat_type_t;


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

typedef struct session_web_stat_struct session_web_stat_t;
typedef struct session_ftp_stat_struct session_ftp_stat_t;
typedef struct session_rtp_stat_struct session_rtp_stat_t;
typedef struct session_ssl_stat_struct session_ssl_stat_t;

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

	uint64_t sum_rtt[2];
	uint64_t rtt_min_usec[2];
	uint64_t rtt_max_usec[2];
	uint64_t rtt_avg_usec[2];
	uint64_t rtt_counter[2];
	uint64_t retransmission_count;

	bool is_touched;
	struct timeval dtt_start_time;
	uint64_t rtt_at_handshake;

	bool dtt_seen;
	bool is_classified;

	uint16_t content_class;

	//sub statistic (e.g., HTTP) beyond main stat (IP)
	session_stat_type_t app_type;

	union{
		session_web_stat_t *web;
		session_ftp_stat_t *ftp;
		session_rtp_stat_t *rtp;
		session_ssl_stat_t *ssl;
	}apps;
#endif

} session_stat_t;



//This function must be called when starting a session
session_stat_t *session_report_callback_on_starting_session ( const ipacket_t * ipacket );

/**
 * This function must be called on each coming packet
 */
int session_report_callback_on_receiving_packet(const ipacket_t * ipacket, session_stat_t * session_stat);

void session_report_callback_on_ending_session(const mmt_session_t * dpi_session, session_stat_t * session_stat, dpi_context_t *context);

void session_report_callback_on_timer(const mmt_session_t * dpi_session, session_stat_t * session_stat, dpi_context_t *context);
/**
 * Returns 1 if the given session is a microflow, O otherwise
 * @param expired_session pointer to the session context to check
 * @return 1 if the given session is a microflow, O otherwise
 */
static inline bool is_micro_flow(const mmt_session_t * expired_session) {
//    mmt_probe_context_t * probe_context = get_probe_context_config();
//
//    if (probe_context->microf_enable == 1){
//        if ((get_session_packet_count(expired_session) <= probe_context->microf_pthreshold) || (get_session_byte_count(expired_session) <= probe_context->microf_bthreshold)) {
//            return true;
//        }
//    }
    return false;
}



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
bool session_report_register( mmt_handler_t *dpi_handler, session_report_conf_t *config );

#endif /* SRC_MODULES_DPI_HEADER_H_ */