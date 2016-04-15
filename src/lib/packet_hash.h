/*
 * packet_hash.h
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#ifndef SRC_QUEUE_PACKET_HASH_H_
#define SRC_QUEUE_PACKET_HASH_H_

#include <stdint.h>
#include <sys/types.h>
/**
 * Hash function of an Ethernet packet
 */
uint32_t get_packet_hash_number( const u_char *pdata, size_t len );

#endif /* SRC_QUEUE_PACKET_HASH_H_ */
