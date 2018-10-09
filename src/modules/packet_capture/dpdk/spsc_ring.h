/*
 * sp_sc_ring.h
 *
 *  Created on: Sep 28, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_PACKET_CAPTURE_DPDK_SPSC_RING_H_
#define SRC_MODULES_PACKET_CAPTURE_DPDK_SPSC_RING_H_

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <rte_atomic.h>


typedef struct spsc_ring_struct{
	//producer
    rte_atomic32_t _head;
    uint32_t _cache_free;

    //consumer
    rte_atomic32_t _tail;
    uint32_t _cache_count;


	uint32_t _size;
    void **_data;
}spsc_ring_t;

static inline  spsc_ring_t *ring_create( uint32_t size ){
	spsc_ring_t *ret = malloc( sizeof( spsc_ring_t ) );
	if( ret == NULL )
		return NULL;

	ret->_data = malloc( sizeof( void * ) * size );
	if( ret->_data == NULL ){
		free( ret );
		return NULL;
	}

	ret->_size = size;
	rte_atomic32_init( & ret->_head );
	rte_atomic32_init( & ret->_tail );
	ret->_cache_count = 0;
	ret->_cache_free = size;

	return ret;
}
static inline void ring_free( spsc_ring_t *q ){
	if( q == NULL ) return;
	if( q->_data ) free( q->_data );
	free( q );
}

static inline  uint32_t ring_enqueue_bulk( spsc_ring_t *q, void **data, uint32_t len  ){
	int i;
	uint32_t h = rte_atomic32_read( &q->_head ), tail;

	if( q->_cache_free < len ){
		tail = rte_atomic32_read( &q->_tail );

		if( tail < h )
			q->_cache_free = tail + q->_size - h;
		else if( tail == h )
			q->_cache_free = q->_size;
		else
			q->_cache_free = tail - h;

	/* tail can only increase since the last time we read it, which means we can only get more space to push into.
			 If we still have space left from the last time we read, we don't have to read again. */
		if( q->_cache_free < len )
			return 0;
	}

	//not full
	for( i=0; i<len; i++ ){
		q->_data[ h ] = data[i];

		h += 1;
		if( h == q->_size )
			h = 0;
	}

	q->_cache_free -= len;

	rte_atomic32_set( &q->_head, h );

	return len;
}

static inline uint32_t ring_dequeue_burst( spsc_ring_t *q, void **val, uint32_t len ){
	int i;
	uint32_t t = rte_atomic32_read( &q->_tail ), head;

	if(  q->_cache_count == 0 ){
		head = rte_atomic32_read ( &q->_head );

		if( head >= t )
			q->_cache_count = head - t;
		else
			q->_cache_count = head + q->_size - t;

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
		if( q->_cache_count == 0 )
			return 0;
	}

	if( len > q->_cache_count )
		len = q->_cache_count;

	for( i=0; i<len; i++ ){
		val[i] = q->_data[ t ];

		t += 1;
		if( t == q->_size )
			t = 0;
	}

	q->_cache_count -= len;

	rte_atomic32_set( &q->_tail, t );
	return len;
}


#endif /* SRC_MODULES_PACKET_CAPTURE_DPDK_SPSC_RING_H_ */
