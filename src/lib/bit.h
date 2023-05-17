/*
 * bit.h
 *
 *  Created on: May 15, 2023
 *      Author: nhnghia
 *
 *  This file implements a simple array of bits.
 *  Each bit receives either 0 or 1 as values.
 *
 */

#ifndef SRC_LIB_BIT_H_
#define SRC_LIB_BIT_H_

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct{
	size_t  nb_bit;
	uint8_t *data;
} bit_t;

/**
 * Initialize
 * @param nb_bit
 * @return
 */
bit_t* bit_create( size_t nb_bit ){
	bit_t *ret = malloc( sizeof( bit_t ));
	ret->nb_bit = nb_bit;

	//number of bytes to contain "nb_bit" bits
	size_t nb_bytes = nb_bit / 8; // index / 8;
	//e.g., need 2 bytes to contain 10 bits
	if( nb_bytes * 8 < nb_bit )
		nb_bytes += 1;

	//allocate, then initialize zero
	ret->data = calloc( nb_bytes, sizeof(uint8_t) );
	return ret;
}

void bit_free( bit_t *bit ){
	if( bit ){
		if( bit->data )
			free( bit->data );
		free( bit );
	}
}

bool bit_set( bit_t *bit, size_t index ){
	if( index >= bit->nb_bit )
		return false;

	size_t  i = index >>  3; // index / 8
	uint8_t j = index  &  7; // index % 8
	bit->data[i] |= (1 << j);

	return true;
}

bool bit_get( bit_t *bit, size_t index ){
	if( index >= bit->nb_bit )
		return false;

	size_t  i = index >>  3; // index / 8
	uint8_t j = index  &  7; // index % 8
	return (bit->data[i] & (1 << j));
}

#endif /* SRC_LIB_BIT_H_ */
