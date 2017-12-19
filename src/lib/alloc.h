/*
 * alloc.h
 *
 *  Created on: Dec 13, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_ALLOC_H_
#define SRC_LIB_ALLOC_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include "optimization.h"
#include "log.h"

//TODO: remove this block
//#define DPDK_MODULE
//#ifndef PCAP_MODULE
//#define PCAP_MODULE
//#endif

#define SECURITY_MODULE
#define REDIS_MODULE
#define KAFKA_MODULE
#define NETCONF_MODULE

static inline void* alloc( size_t size ){
	void *ret = malloc( size );
	if( unlikely( ret == NULL )){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		exit( 1 );
	}
	return ret;
}

static inline void xfree( void *x ){
	if( likely( x != NULL ))
		free( x );
}


#define EXPECT( expected, ret )\
	while( unlikely( ! (expected) ) )\
		return ret
#endif /* SRC_LIB_ALLOC_H_ */
