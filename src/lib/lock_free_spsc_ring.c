/*
 * lock_free_spsc_ring.c
 *
 *  Created on: 31 mars 2016
 *      Author: nhnghia
 *
 * An implementation of Lamport queue without lock
 * based on https://github.com/blytkerchan/Lamport
 */
#include <stdlib.h>
#include <stdatomic.h>
#include "lock_free_spsc_ring.h"

void queue_free( lock_free_spsc_ring_t *q ){
	if( q == NULL ) return;
	if( q->_data ) free( q->_data );
	free( q );
}
void queue_init( lock_free_spsc_ring_t *q, uint32_t size ){
	q->_data = malloc( sizeof( uint32_t) * size );
	q->_size = size;
	q->_head = q->_tail = 0;
	q->_cached_head = q->_cached_tail = 0;
}
int  queue_push( lock_free_spsc_ring_t *q, uint32_t val  ){
	uint32_t h;
	h = q->_head;

	//I always let 2 available elements between head -- tail
	//1 empty element for future inserting, 1 element being reading by the consumer
	if( ( h + 3 ) % ( q->_size ) == q->_cached_tail )
		q->_cached_tail = atomic_load_explicit( &q->_tail, memory_order_acquire );

	/* tail can only increase since the last time we read it, which means we can only get more space to push into.
		 If we still have space left from the last time we read, we don't have to read again. */
	if( ( h + 3 ) % ( q->_size ) == q->_cached_tail )
		return QUEUE_FULL;

	//not full
	q->_data[ h ] = val;
	atomic_store_explicit( &q->_head, (h +1) % q->_size, memory_order_release );

	return QUEUE_SUCCESS;
}
int  queue_pop ( lock_free_spsc_ring_t *q, uint32_t *val ){
	uint32_t  t;
	t = q->_tail;

	if( q->_cached_head == t )
		q->_cached_head = atomic_load_explicit ( &q->_head, memory_order_acquire );

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
	if( q->_cached_head == t )
		return QUEUE_EMPTY;

	//not empty
	*val = q->_data[ t ];

	atomic_store_explicit( &q->_tail, (t+1) % q->_size, memory_order_release );

	return QUEUE_SUCCESS;
}
