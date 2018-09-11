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
#include "unit.h"
#include "tools.h"

static ALWAYS_INLINE void assign_16bytes( void *dest, const void *source){
	const uint64_t *s = (uint64_t *)source;
	uint64_t *d = (uint64_t *)dest;
	d[0] = s[0];
	d[1] = s[1];
}

static ALWAYS_INLINE void assign_8bytes( void *dest, const void *source){
	const uint64_t *s = (uint64_t *)source;
	uint64_t *d = (uint64_t *)dest;
	d[0] = s[0];
}

/**
 * Assign 6 bytes from #source to #dest
 * @param dest
 * @param source
 */

static ALWAYS_INLINE void assign_6bytes( void *dest, const void *source){
	const uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
	d[1] = s[1];
	d[2] = s[2];
}

static ALWAYS_INLINE void assign_4bytes( void *dest, const void *source){
	const uint32_t *s = (uint32_t *)source;
	uint32_t *d = (uint32_t *)dest;
	d[0] = s[0];
}

static ALWAYS_INLINE void assign_2bytes( void *dest, const void *source){
	const uint16_t *s = (uint16_t *)source;
	uint16_t *d = (uint16_t *)dest;
	d[0] = s[0];
}

#endif /* SRC_LIB_MEMORY_H_ */
