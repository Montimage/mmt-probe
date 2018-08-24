/*
 * dpdk_malloc.h
 *
 *  Created on: Aug 23, 2018
 *          by: Huu Nghia Nguyen
 *
 * Include this file to .c file to use DPDK memory allocation.
 * The functions in this file must not be called before rte_eal_init.
 */

#ifndef SRC_MODULES_PACKET_CAPTURE_DPDK_DPDK_MALLOC_H_
#define SRC_MODULES_PACKET_CAPTURE_DPDK_DPDK_MALLOC_H_

#include <rte_malloc.h>
#include <rte_memcpy.h>
#include "../../../lib/log.h"
#include "../../../lib/optimization.h"

static inline void *dpdk_malloc( size_t size){
	void *x = rte_malloc( NULL, size, 0 );
	if( unlikely( x == NULL )){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		abort();
	}
	return x;
}

static inline void *dpdk_zalloc( size_t size){
	void *x = rte_zmalloc( NULL, size, 0 );
	if( x == NULL ){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		abort();
	}
	return x;
}

static inline void dpdk_free( void *x ){
	rte_free( x );
}

static inline void* dpdk_realloc( void *x, size_t size ){
	x = rte_realloc(x, size, 0);
	if( x == NULL ){
		log_write( LOG_EMERG, "Not enough memory to reallocate %zu bytes", size );
		abort();
	}
	return x;
}

static inline void *dpdk_memdup( const void *src, size_t size ){
	void *dst = dpdk_malloc( size );
	rte_memcpy(dst, src, size);
	return dst;
}

static inline char *dpdk_strdup( const char *src ){
	size_t size = strlen( src );
	void *dst = dpdk_malloc( size );
	rte_memcpy(dst, src, size);
	return dst;
}

#endif /* SRC_MODULES_PACKET_CAPTURE_DPDK_DPDK_MALLOC_H_ */
