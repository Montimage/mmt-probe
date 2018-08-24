/*
 * malloc.h
 *
 *  Created on: Aug 24, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_MALLOC_H_
#define SRC_LIB_MALLOC_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "optimization.h"
#include "log.h"

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

static ALWAYS_INLINE void * mmt_memdup( const void *src, size_t size ) {
	if( size == 0 )
		return NULL;
	void *tmp = mmt_alloc( size );
	memcpy( tmp, src, size );
	return tmp;
}

static ALWAYS_INLINE char * mmt_strndup( const char *str, size_t size ) {
	char *s = mmt_memdup( str, size +1 );
	s[ size ] = '\0'; //well NULL-terminated
	return s;
}

#endif /* SRC_LIB_MALLOC_H_ */
