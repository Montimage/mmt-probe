/*
 * ring.h
 *
 *  Created on: Jun 7, 2018
 *          by: Huu Nghia Nguyen
 *
 * A simple implementation of buffer ring
 */

#ifndef RING_H_
#define RING_H_

#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifndef RING_ELEM_TYPE
#define RING_ELEM_TYPE void *
#endif

typedef struct {
	uint32_t head;
	uint32_t tail;
	uint32_t size;
	RING_ELEM_TYPE buffer[];
} ring_t;

static inline ring_t* ring_create( uint32_t size){
	if( size == 0 )
		return NULL;

	ring_t *ring = malloc( sizeof( ring_t) + sizeof( RING_ELEM_TYPE ) * size );

	if(ring == NULL )
		return NULL;

	ring->head = 0;
	ring->tail = 0;
	ring->size = size;

	return ring;
}

static inline void ring_free( ring_t *ring ){
	free( ring );
}

static inline bool ring_enqueue(ring_t * ring, RING_ELEM_TYPE data){
	// We determine "full" case by head being one position behind the tail
	// Note that this means we are wasting one space in the buffer!
	// Instead, you could have an "empty" flag and determine buffer full that way
	uint32_t next_pos = (ring->head + 1) % ring->size;
    if( next_pos == ring->tail)
    	return false;

    //put data to head
	ring->buffer[ ring->head ] = data;
	ring->head = next_pos;

	return true;
}

static inline bool ring_dequeue(ring_t * ring, RING_ELEM_TYPE *data){
	//ring is empty
	if( ring->head == ring->tail )
		return false;

	if( data != NULL )
		*data = ring->buffer[ring->tail];

	ring->tail = (ring->tail + 1) % ring->size;

	return true;
}

static inline void ring_clear( ring_t *ring ){
	ring->head = 0;
	ring->tail = 0;
}
#endif /* RING_H_ */
