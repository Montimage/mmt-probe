/*
 * data_spsc_ring.h
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#ifndef SRC_QUEUE_DATA_SPSC_RING_H_
#define SRC_QUEUE_DATA_SPSC_RING_H_

#include <stdint.h>
#include "lock_free_spsc_ring.h"

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
int data_spsc_ring_get_tmp_element( const data_spsc_ring_t *q, void **tmp_element );

/**
 * Must be called by producer
 * Try to push the temporary element into the queue
 * @return: 0 if success
 *          1 if q is null
 *          2 if the queue is full
 *          3 if the temporary element does not exist (e.g., it is freed by user)
 */
int data_spsc_ring_push_tmp_element( data_spsc_ring_t *q );

/**
 * Must being called by consumer
 * Try to pop an element from the ring
 * @param **val: pointer points to the element
 * @return: 0 if success
 *          1 if q is null
 *          2 if the queue is empty
 */
int data_spsc_ring_pop ( data_spsc_ring_t *q, void **val );


/**
 * Free the ring
 */
void data_spsc_ring_free( data_spsc_ring_t *q );

#endif /* SRC_QUEUE_DATA_SPSC_RING_H_ */
