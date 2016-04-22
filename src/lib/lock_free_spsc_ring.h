/*
 * lock_free_spsc_ring.c
 *
 *  Created on: 31 mars 2016
 *      Author: nhnghia
 */

#ifndef SRC_QUEUE_LOCK_FREE_SPSC_RING_H_
#define SRC_QUEUE_LOCK_FREE_SPSC_RING_H_

#include <stdint.h>
//#include <pthread.h>

#define QUEUE_EMPTY  -1
#define QUEUE_FULL   -2
#define QUEUE_SUCCESS 0

typedef struct lock_free_spsc_ring_struct
{
    volatile uint32_t _head __attribute__ ((aligned(64)));
    volatile uint32_t _tail __attribute__ ((aligned(64)));

    uint32_t _cached_head, _cached_tail, _size;
    uint32_t *_data;
}lock_free_spsc_ring_t;

void queue_init( lock_free_spsc_ring_t *q, uint32_t size );
int  queue_push( lock_free_spsc_ring_t *q, uint32_t val  );
int  queue_pop ( lock_free_spsc_ring_t *q, uint32_t *val );
void queue_free( lock_free_spsc_ring_t *q );

#endif /* SRC_QUEUE_LOCK_FREE_SPSC_RING_H_ */
