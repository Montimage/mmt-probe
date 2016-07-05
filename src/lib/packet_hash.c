/*
 * packet_hash.c
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_hash.h"
#include "optimization.h"

#define __HASH_TABLE_SIZE 100000



static uint32_t _dispatcher( uint64_t nu ){
	static uint64_t hash_table[ __HASH_TABLE_SIZE ];
	static uint32_t length = 0;
	static uint32_t i;

	//check if this number exists in the hash table
	for( i=0; i<length; i++ )
		if( hash_table[i] == nu )
			return i;

	//if not, add it
	hash_table[ length ] = nu;
	length ++;

	if( unlikely( length >= __HASH_TABLE_SIZE ))
		length = 0;

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
	//static uint16_t p1, p2;
	static uint16_t ip_src_off;
	static uint8_t proto_id;

	if (len < 38) return 0; //TODO: this is not elegant check IP, IPv6 etc.

	if( packet == NULL)
		return 0;

	eth = (struct __eth_hdr_struct *) packet;


	if ( likely( ntohs(eth->h_proto) == 0x0800 ) ) {
		ip_src_off = 26;
	}
	//vlan
	else if ( likely(ntohs(eth->h_proto) == 0x8100)) {
		ip_src_off = 30;
	} else {
		return 0;
	}

	a1 = *((uint32_t *) &packet[ip_src_off]);
	a2 = *((uint32_t *) &packet[ip_src_off + 4]);

	/*proto_id = *((uint8_t *) &packet[ ip_src_off - 3 ]);
	//src and dst ports of TCP or UDP
	if( likely(proto_id == 6 || proto_id == 17 )){
		p1 = *((uint16_t *) &packet[ ip_src_off + 8]);
		p2 = *((uint16_t *) &packet[ ip_src_off + 8 + 2]);
	}
	else
		p1 = p2 = 0;*/

	//p1 = ntohs( p1 );
	//p2 = ntohs( p2 );

//	if ((ntohl(a1) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
//		return ntohl(a1);
//	}
//
//	if ((ntohl(a2) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
//		return ntohl(a2);
//	}
//
	/*
	printf("%s src: %03d.%03d.%03d.%03d, dst: %03d.%03d.%03d.%03d, port_src: %d, port_dst: %d\n",
			proto_id == 6? "TCP" :( proto_id == 17? "UDP" : "---"),
			(a1 >> 24), ((a1 << 8) >> 24), ((a1 << 16) >> 24), ((a1 << 24) >> 24),
			(a2 >> 24), ((a2 << 8) >> 24), ((a2 << 16) >> 24), ((a2 << 24) >> 24),
			htons( p1 ), htons( p2 )
			);
	//exit( 0 );
	*/
	//a1 = (a1 & a2) ^ (a1 | a2);
//	a1 = (a1 >> 24) + (a1 >> 16) + (a1 >> 8) + a1;
//	a2 = (a2 >> 24) + (a2 >> 16) + (a2 >> 8) + a2;

	//return _dispatcher( a1 + a2 + p1 + p2 );
	return _dispatcher( a1 + a2);
}
