/*
 * data_spsc_ring.c
 *
 *  Created on: 14 avr. 2016
 *          by: Huu Nghia
 */

#include <stdlib.h>
#include "data_spsc_ring.h"
#include "lock_free_spsc_ring.h"

static inline void __free_data_spsc_ring( data_spsc_ring_t *q){
	uint32_t i;

	if( q == NULL ) return;
	if( q->_data != NULL ){
		for( i=0; i<q->_size; i++){

			if( q->_data[i] != NULL){

				free( q->_data[ i ] );
			}
		}
		free( q->_data );
	}
	queue_free( q->_fifo_index );
}

void data_spsc_ring_free( data_spsc_ring_t *q ){
	__free_data_spsc_ring( q );
	//free( q );
	//q = NULL;
}

/**
 * Initialize a single-producer-single-consumer ring
 * @param data_spsc_ring_t *q
 * @param size: size of the ring
 * @param element_size: number of byte allocated for each element
 * @return: 0 if success
 *          1 if q is null or size < 1 or element_size = 0
 *          2 if there is not enough memory
 */
int data_spsc_ring_init( data_spsc_ring_t *q, uint32_t size, uint32_t element_size ){
	int i,j;
	if( q == NULL || size < 1 || element_size == 0 )
		return 1;
	q->_size = size + 2;
	q->_fifo_index = malloc( sizeof( lock_free_spsc_ring_t ));
	if( q->_fifo_index == NULL )
		return 2;
	queue_init( q->_fifo_index, q->_size );

	q->_data = malloc( sizeof( void *) * q->_size );
	if( q->_data == NULL ){
		queue_free( q->_fifo_index );
		return 2;
	}

	for( i=0; i<q->_size; i++){
		q->_data[ i ] = malloc( element_size );
		//not enough memory
		if( q->_data[i] == NULL ){
			//release memory being allocated
			queue_free( q->_fifo_index );
			for( j=0; j<i; j++ )
				free( q->_data[j] );
			free( q->_data );
			return 2;
		}
	}

	EXEC_ONLY_IN_VALGRIND_MODE( DRD_IGNORE_VAR( q )  );
	EXEC_ONLY_IN_VALGRIND_MODE( DRD_IGNORE_VAR( q->_size )  );
	EXEC_ONLY_IN_VALGRIND_MODE( DRD_IGNORE_VAR( q->_fifo_index )  );
	EXEC_ONLY_IN_VALGRIND_MODE( DRD_IGNORE_VAR( q->_data )  );

	return 0;
}

