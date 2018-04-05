/*
 * alloc.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_MEMORY_H_
#define SRC_LIB_MEMORY_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include "optimization.h"
#include "log.h"
#include "limit.h"
#include "tools.h"

//TODO: remove this block
//#define DPDK_MODULE
//#ifndef PCAP_MODULE
//#define PCAP_MODULE
//#endif

//#define SECURITY_MODULE
//#define REDIS_MODULE
//#define KAFKA_MODULE
//#define NETCONF_MODULE


static inline void* alloc( size_t size ){
	void *ret = malloc( size );
	if( unlikely( ret == NULL )){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		exit( 1 );
	}
	return ret;
}

static inline void xfree( void *x ){
	free( x );
}


static inline void assign_6bytes( void *dest, void *source){
	uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
}

#define EXPECT( expected, ret )\
	while( unlikely( ! (expected) ) )\
		return ret
#endif /* SRC_LIB_MEMORY_H_ */
