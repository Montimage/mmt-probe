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
#include <string.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include "optimization.h"
#include "log.h"
#include "limit.h"
#include "tools.h"

/**
 * Allocate a memory segment.
 * Abort when not enough memory to allocate
 * @param size
 */
static ALWAYS_INLINE void* mmt_alloc( size_t size ){
	void *ret = malloc( size );
	if( unlikely( ret == NULL )){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		abort();
	}
	return ret;
}

/**
 * Allocate memory and initialize to zero
 * @param size
 */
static ALWAYS_INLINE void *mmt_alloc_and_init_zero( size_t size ){
	void *ret = calloc( 1, size );
	if( unlikely( ret == NULL )){
		log_write( LOG_EMERG, "Not enough memory to allocate %zu bytes", size );
		abort();
	}
	return ret;
}

static ALWAYS_INLINE void mmt_probe_free( void *x ) {
	free( x );
}

static ALWAYS_INLINE char * mmt_strdup( const char *str ) {
	return strdup( str );
}

static ALWAYS_INLINE char * mmt_strndup( const char *str, size_t size ) {
	return strndup( str, size );
}

/**
 * Assign 6 bytes from #source to #dest
 * @param dest
 * @param source
 */

static ALWAYS_INLINE void assign_6bytes( void *dest, void *source){
	uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
}

static ALWAYS_INLINE void assign_4bytes( void *dest, void *source){
	uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
	d[1] = s[1];
}

static ALWAYS_INLINE void assign_2bytes( void *dest, void *source){
	uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
}


#define EXPECT( expected, ret )\
	while( unlikely( ! (expected) ) )\
		return ret
#endif /* SRC_LIB_MEMORY_H_ */
