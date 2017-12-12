/*
 * packet_hash.h
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */
#ifdef PCAP
#ifndef SRC_QUEUE_PACKET_HASH_H_
#define SRC_QUEUE_PACKET_HASH_H_

#include <stdint.h>
#include <sys/types.h>
#include "optimization.h"

struct __eth_hdr_struct {
	uint8_t h_dest[6];
	uint8_t h_source[6];
	uint16_t h_proto;
};

uint32_t _get_index( uint32_t nu );

/**
 * Hash function of an Ethernet packet
 */
static inline uint32_t __attribute__((always_inline))
	get_packet_hash_number( const uint8_t *packet, size_t len ){
	//struct __eth_hdr_struct  * eth;

	uint32_t a1, a2;
	//static uint16_t p1, p2;
	uint16_t ip_src_off;
	uint8_t h_proto;
	uint16_t proto_id = 0;

	if ( unlikely( len < 38)) return 0; //TODO: this is not elegant check IP, IPv6 etc.

	//eth = (struct __eth_hdr_struct *) packet;
	h_proto = packet[12];

	if ( likely( h_proto == 0x08 ) ) {
		ip_src_off = 26;
	}
	//vlan
	else if ( h_proto == 0x81 ) {
		ip_src_off = 30;
	} else {
		return 0;
	}

//	return ( packet[ip_src_off] | packet[ip_src_off + 4] );
//
	a1 = *((uint32_t *) &packet[ ip_src_off     ]);
	a2 = *((uint32_t *) &packet[ ip_src_off + 4 ]);
//
//	/*proto_id = *((uint8_t *) &packet[ ip_src_off - 3 ]);
//	//src and dst ports of TCP or UDP
//	if( likely(proto_id == 6 || proto_id == 17 )){
//		p1 = *((uint16_t *) &packet[ ip_src_off + 8]);
//		p2 = *((uint16_t *) &packet[ ip_src_off + 8 + 2]);
//	}
//	else
//		p1 = p2 = 0;*/
//
//	//p1 = ntohs( p1 );
//	//p2 = ntohs( p2 );
//
////	if ((ntohl(a1) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
////		return ntohl(a1);
////	}
////
////	if ((ntohl(a2) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
////		return ntohl(a2);
////	}
////
//
//	printf("%s src: %03d.%03d.%03d.%03d, dst: %03d.%03d.%03d.%03d \n",
//			proto_id == 6? "TCP" :( proto_id == 17? "UDP" : "---"),
//			(a1 >> 24), ((a1 << 8) >> 24), ((a1 << 16) >> 24), ((a1 << 24) >> 24),
//			(a2 >> 24), ((a2 << 8) >> 24), ((a2 << 16) >> 24), ((a2 << 24) >> 24)
//			);
//	//exit( 0 );
//
//	//a1 = (a1 & a2) ^ (a1 | a2);
////	a1 = (a1 >> 24) + (a1 >> 16) + (a1 >> 8) + a1;
////	a2 = (a2 >> 24) + (a2 >> 16) + (a2 >> 8) + a2;
//
	return _get_index( a1 + a2);
}

#endif /* SRC_QUEUE_PACKET_HASH_H_ */
#endif
