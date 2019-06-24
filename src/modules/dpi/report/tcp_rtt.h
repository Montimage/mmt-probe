/*
 * tcp_rtt.h
 *
 *  Created on: May 31, 2019
 *          by: Huu-Nghia
 *
 *
 *  This module calculates RTT of data packets in a TCP stream.
 *  - tcp_rtt_init must be called when stream is initialized
 *  - tcp_rtt_add_packet must be called on each packet of the tream
 *  - tcp_rtt_release must be called at the end of the stream to release resource.
 *
 *
 *  Each time when a packet comes, the function tcp_rtt_add_packet is called to update seq_num, ack_num, payload_len.
 *  It  updates seq_num and data_len to the list of the current direction.
 *  It also check, for the inverted direction, whether there exist some packets that are acknowledged by the given ack_num.
 *  If this is the case, it returns the number of packets. It output also in usec the interval between the latest packet being acknowledged and the current one.
 *
 */

#ifndef SRC_MODULES_DPI_REPORT_TCP_RTT_H_
#define SRC_MODULES_DPI_REPORT_TCP_RTT_H_

#include <stdlib.h>
#include <stdint.h>


typedef struct tcp_rtt_struct tcp_rtt_t;

/**
 * Initialize data structure
 * Need to be called at beginning of TCP session.
 */
tcp_rtt_t *tcp_rtt_init();

/**
 * Add packet to the list
 * @output usec interval, in nano second, between the last data packet and the ack packet if pkt acks some packets storing in the list
 * @return number of packets being acknowledged
 */
uint32_t tcp_rtt_add_packet( tcp_rtt_t *rtt, uint8_t direction, uint32_t ack_num, uint32_t seq_num, uint16_t len, struct timeval ts, uint64_t *usec );

/**
 * Release resources.
 * Need to be called at the end of TCP session
 */
void tcp_rtt_release( tcp_rtt_t *rtt );

#endif /* SRC_MODULES_DPI_REPORT_TCP_RTT_H_ */
