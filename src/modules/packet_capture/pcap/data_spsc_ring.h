/*
 * data_spsc_ring.h
 *
 *  Created on: 14 avr. 2016
 *          by: Huu Nghia
 */

#ifndef SRC_QUEUE_DATA_SPSC_RING_H_
#define SRC_QUEUE_DATA_SPSC_RING_H_

#include <stdint.h>
#include "data_spsc_ring.h"
#include "lock_free_spsc_ring.h"
#include "../../../lib/optimization.h"
#include "../../../lib/valgrind.h"

typedef struct data_spsc_ring_struct{
	void **_data;
	uint32_t _size;
	lock_free_spsc_ring_t *_fifo_index;
}data_spsc_ring_t;


/**
 * Initialize a single-producer-single-consumer ring
 * @param data_spsc_ring_t *q
 * @param size: size of the ring
 * @param element_size: number of byte allocated for each element
 * @return: 0 if success
 *          1 if q is null or size < 1 or element_size = 0
 *          2 if there is not enough memory
 */
int data_spsc_ring_init( data_spsc_ring_t *q, uint32_t size, uint32_t element_size );

/**
 * Must be called by producer
 * Get a temporary element through that user can modify its content before being inserted to the ring
 * User must not free this pointer.
 * @return: 0 if success
 *          1 if q is null
 */
static ALWAYS_INLINE int data_spsc_ring_get_tmp_element( const data_spsc_ring_t *q, void **tmp_element ){
//	if( unlikely( q == NULL ) )
//		return 1;

	*tmp_element = q->_data[ q->_fifo_index->_head ];

	return QUEUE_SUCCESS;
}

/**
 * Must be called by producer
 * Try to push the temporary element into the queue
 * @return: 0 if success
 *          1 if q is null
 *          2 if the queue is full
 *          3 if the temporary element does not exist (e.g., it is freed by user)
 */
static ALWAYS_INLINE int data_spsc_ring_push_tmp_element( data_spsc_ring_t *q ){
//	if( unlikely( q == NULL ) )
//		return 1;

//	if( unlikely( q->_data[ q->_fifo_index->_head ] == NULL ))
//		return 3;

	return queue_push( q->_fifo_index, q->_fifo_index->_head );
}

/**
 * Must being called by consumer
 * Try to pop an element from the ring
 * @param **val: pointer points to the element
 * @return: 0 if success
 *          1 if q is null
 *          2 if the queue is empty
 */
static ALWAYS_INLINE int data_spsc_ring_pop ( data_spsc_ring_t *q, void **val ){
	uint32_t tail;
//	if( unlikely( q == NULL ) )
//		return 1;
	if( queue_pop( q->_fifo_index, &tail) == QUEUE_EMPTY )
		return QUEUE_EMPTY;

	*val = q->_data[ tail ];
	return QUEUE_SUCCESS;
}

static ALWAYS_INLINE int data_spsc_ring_pop_bulk ( const data_spsc_ring_t *q, uint32_t *tail ){
	return queue_pop_bulk( q->_fifo_index, tail);
}

static ALWAYS_INLINE void* data_spsc_ring_get_data( const data_spsc_ring_t *q, uint32_t index ){
	EXEC_ONLY_IN_VALGRIND_MODE( ANNOTATE_HAPPENS_AFTER( &(q->_fifo_index->_data) ));
	EXEC_ONLY_IN_VALGRIND_MODE( ANNOTATE_HAPPENS_AFTER( &(q->_fifo_index) ));
	return q->_data[ q->_fifo_index->_data[ index ] ];
}

static ALWAYS_INLINE void data_spsc_ring_update_tail( const data_spsc_ring_t *q, uint32_t tail, uint32_t size ){
	queue_update_tail( q->_fifo_index, tail, size );
}
/**
 * Free the ring
 */
void data_spsc_ring_free( data_spsc_ring_t *q );

#endif /* SRC_QUEUE_DATA_SPSC_RING_H_ */
