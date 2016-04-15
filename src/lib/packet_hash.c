/*
 * packet_hash.c
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include "packet_hash.h"
#include "optimization.h"

#define __HASH_TABLE_SIZE 10000



static uint32_t _dispatcher( uint32_t nu ){
	static uint32_t hash_table[ __HASH_TABLE_SIZE ];
	static uint32_t length = 0;
	static uint32_t i;

	if( unlikely( length >= __HASH_TABLE_SIZE )) length = 0;

	//check if this number exists in the hash table
	for( i=0; i<length; i++ )
		if( hash_table[i] == nu )
			return i;

	//if not, add it
	hash_table[ length ] = nu;
	length ++;
	return length - 1;
}



struct __eth_hdr_struct {
	uint8_t h_dest[6];
	uint8_t h_source[6];
	uint16_t h_proto;
};

struct __ipv4_hdr_struct {

};

uint32_t get_packet_hash_number( const u_char *packet, size_t len ){
	static struct __eth_hdr_struct  * eth;

	static uint32_t a1, a2;
	static uint16_t p1, p2;
	static uint16_t ip_src_off, ip_dst_off, port_src_off;
	if (len < 38) return 0; //TODO: this is not elegant check IP, IPv6 etc.

	eth = (struct __eth_hdr_struct *) packet;


	if ( likely( ntohs(eth->h_proto) == 0x0800 ) ) {
		ip_src_off = 26;
		ip_dst_off = 30;
		port_src_off = 38;
	} else if ( likely(ntohs(eth->h_proto) == 0x8100)) {
		ip_src_off = 30;
		ip_dst_off = 34;
		port_src_off = 42;
	} else {
		return 0;
	}

	a1 = *((uint32_t *) &packet[ip_src_off]);
	a2 = *((uint32_t *) &packet[ip_dst_off]);

	p1 = *((uint16_t *) &packet[port_src_off]);
	p2 = *((uint16_t *) &packet[port_src_off + 1]);

	p1 = p2 = 0;

	//p1 = ntohl( p1 );
	//p2 = ntohl( p2 );

//	if ((ntohl(a1) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
//		return ntohl(a1);
//	}
//
//	if ((ntohl(a2) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
//		return ntohl(a2);
//	}
//
	/*
	printf("src: %03d.%03d.%03d.%03d, dst: %03d.%03d.%03d.%03d, port_src: %d, port_dst: %d, %d %d\n",
			(a1 >> 24), ((a1 << 8) >> 24), ((a1 << 16) >> 24), ((a1 << 24) >> 24),
			(a2 >> 24), ((a2 << 8) >> 24), ((a2 << 16) >> 24), ((a2 << 24) >> 24),
			p1, p2
			, packet[port_src_off], packet[port_src_off + 1]
			);
	exit( 0 );
	*/
	//a1 = (a1 & a2) ^ (a1 | a2);
//	a1 = (a1 >> 24) + (a1 >> 16) + (a1 >> 8) + a1;
//	a2 = (a2 >> 24) + (a2 >> 16) + (a2 >> 8) + a2;
	a1 = a1 + a2 + p1 + p2;

	return _dispatcher( a1 );
}
