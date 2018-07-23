/*
 * lock_free_spsc_ring.c
 *
 *  Created on: 31 mars 2016
 *          by: Huu Nghia
 */

#ifndef SRC_QUEUE_LOCK_FREE_SPSC_RING_H_
#define SRC_QUEUE_LOCK_FREE_SPSC_RING_H_

#include <stdint.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdio.h>
#include "../../../lib/valgrind.h"
#include "../../../lib/optimization.h"

#define QUEUE_EMPTY  -1
#define QUEUE_FULL   -2
#define QUEUE_SUCCESS 0


//this lib needs to be compiled by gcc >= 4.9
#define GCC_VERSION (__GNUC__ * 10000        \
                     + __GNUC_MINOR__ * 100  \
                     + __GNUC_PATCHLEVEL__)

// Test for GCC < 4.9.0
#if GCC_VERSION < 40900
	#warning Need gcc >= 4.9
#endif

typedef struct lock_free_spsc_ring_struct
{
    volatile uint32_t _head __attribute__ ((aligned(64)));
    volatile uint32_t _tail __attribute__ ((aligned(64)));

    uint32_t _cached_head, _cached_tail, _size;
    uint32_t *_data;
}lock_free_spsc_ring_t;

#ifdef atomic_load_explicit
#undef atomic_load_explicit
#endif

#ifdef atomic_store_explicit
#undef atomic_store_explicit
#endif

#define atomic_load_explicit( x, y )    __sync_fetch_and_add( x, 0 )
#define atomic_store_explicit( x, y, z) __sync_lock_test_and_set( x, y)
//#define atomic_store_explicit( x, y, z) __sync_synchronize( *x = y )

void queue_init( lock_free_spsc_ring_t *q, uint32_t size );
void queue_free( lock_free_spsc_ring_t *q );

static ALWAYS_INLINE int queue_push( lock_free_spsc_ring_t *q, uint32_t val  ){
	uint32_t h;
	h = q->_head;

	//I always let 2 available elements between head -- tail
	//1 empty element for future inserting, 1 element being reading by the consumer
	if( ( h + 3 ) % ( q->_size ) == q->_cached_tail ){
		q->_cached_tail = atomic_load_explicit( &q->_tail, memory_order_acquire );

	/* tail can only increase since the last time we read it, which means we can only get more space to push into.
			 If we still have space left from the last time we read, we don't have to read again. */
		if( ( h + 3 ) % ( q->_size ) == q->_cached_tail ) return QUEUE_FULL;
	}

	//not full
	q->_data[ h ] = val;
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_BEFORE( &(q) ));
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_BEFORE( &(q->_data) ));

	atomic_store_explicit( &q->_head, (h +1) % q->_size, memory_order_release );

	return QUEUE_SUCCESS;
}

static ALWAYS_INLINE int queue_pop ( lock_free_spsc_ring_t *q, uint32_t *val ){
	uint32_t  t;
	t = q->_tail;

	if( q->_cached_head == t ){
		q->_cached_head = atomic_load_explicit ( &q->_head, memory_order_acquire );

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
		if( q->_cached_head == t ) return QUEUE_EMPTY;
	}
	//not empty
	*val = q->_data[ t ];

	atomic_store_explicit( &q->_tail, (t+1) % q->_size, memory_order_release );

	return QUEUE_SUCCESS;
}


static ALWAYS_INLINE int queue_pop_bulk ( lock_free_spsc_ring_t *q, uint32_t *val ){
	uint32_t t = q->_tail;

	if( q->_cached_head == t ){
		q->_cached_head = atomic_load_explicit ( &q->_head, memory_order_acquire );

	 /* head can only increase since the last time we read it, which means we can only get more items to pop from.
		 If we still have items left from the last time we read, we don't have to read again. */
		if( q->_cached_head == t ) return QUEUE_EMPTY;
	}

	//not empty
	*val = t;

	if( q->_cached_head > t ){
		return q->_cached_head - t;
	}else{
		return q->_size - t;
	}
}


static ALWAYS_INLINE void queue_update_tail ( lock_free_spsc_ring_t *q, uint32_t tail, uint32_t size ){
	atomic_store_explicit( &q->_tail, (tail + size) % q->_size, memory_order_release );
}
#endif /* SRC_QUEUE_LOCK_FREE_SPSC_RING_H_ */
