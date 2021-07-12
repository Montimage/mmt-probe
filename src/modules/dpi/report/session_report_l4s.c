/*
 * session_report_l4s.c
 *
 *  Created on: Jul 5, 2021
 *      Author: nhnghia
 *
 * This file implements the reports containing L4S information using in Mosaico project:
 * - iat: interval of arrival time between 2 consecutives packets
 * - cws: congestion window size
 * - recovery time: interval between min and max CWS
 * - Queue delay: time spent in queue per packet
 * - Queue occupation: nb of packets presents in the queue
 * - Number of packets marked or dropped
 */

#include "session_report.h"
#include "../../../lib/malloc_ext.h"

typedef struct report_value_struct{
	uint32_t min, max, avg;
}report_value_t;

typedef struct report_queue_struct{
	report_value_t queue_delay;
	report_value_t queue_occupation;
	uint32_t nb_marked_in_queue;
	uint32_t nb_dropped_in_queue;
} report_queue_t;

typedef struct l4s_report_struct{
	report_value_t iat;
	report_value_t cws;
	report_value_t recovery_time;
	report_queue_t ll_queue; //low latency queue
	report_queue_t cl_queue; //classical queue
} l4s_report_t;


struct session_l4s_report_struct{
	struct timeval last_pkt_ts;
	l4s_report_t report;
};

/* we store drops in 5 bits */
#define DROPS_M 2
#define DROPS_E 3

/* we store queue length in 11 bits */
#define QDELAY_M 7
#define QDELAY_E 4

/* Decode float value
 *
 * fl: Float value
 * m_b: Number of mantissa bits
 * e_b: Number of exponent bits
 */
static inline uint32_t fl2int(uint32_t fl, uint32_t m_b, uint32_t e_b)
{
	const uint32_t m_max = 1 << m_b;

	fl &= ((m_max << e_b) - 1);

	if (fl < (m_max << 1)) {
		return fl;
	} else {
		return (((fl & (m_max - 1)) + m_max) << ((fl >> m_b) - 1));
	}
}


static void _decode_l4s_in_ip_identification( uint16_t id, uint32_t *delay, uint32_t *drop ){
	*drop = fl2int(id >> 11, DROPS_M, DROPS_E); // drops stored in 5 bits MSB
	// We don't decode queueing delay here as we need to store it in a table,
	// so defer this to the actual serialization of the table to file
	*delay = id & 2047; // 2047 = 0b0000011111111111
}

static void _ip_identification_handle(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	char *response_value = (char *) attribute->data;
}


//This function is called by session_report.session_report_register to register HTTP extractions
size_t get_session_l4s_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t handlers[] = {
			{.proto_id = PROTO_IP,  .att_id = IP_IDENTIFICATION,   .handler = _ip_identification_handle },
			{.proto_id = PROTO_IP,  .att_id = IP_DF_FLAG,          .handler = NULL },
			{.proto_id = PROTO_IP,  .att_id = IP_PROTO_TOS,        .handler = NULL },
			{.proto_id = PROTO_TCP, .att_id = TCP_ECE,                 .handler = NULL },
	};

	*ret = handlers;
	return (sizeof( handlers ) / sizeof( handlers[0] ));
}
