/*
 * bit.h
 *
 *  Created on: Sep 5, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_LIB_BIT_H_
#define SRC_LIB_BIT_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>


typedef struct{
	uint16_t bit_len;
	uint64_t data[]; //data type must be 64bit
}bit_t;

#define ELEM_BLOCK_SIZE          64 //64 bits per block
#define ELEM_BLOCK_SIZE_POWER_2   6 //2^6 = 64


/**
 * Create a memory segment to bit manipulate on it
 * @param bit_len: number of bit
 * @return
 */
bit_t* bit_create( uint16_t bit_len ){
	//+1 to ensure we have enough, e.g., bit_len = 65 => nb_elems = 2
	uint16_t nb_elems = bit_len / ELEM_BLOCK_SIZE + 1;

	bit_t *ret = malloc( sizeof( bit_t ) + nb_elems * sizeof(uint64_t) );
	if( ret == NULL )
		return NULL;
	ret->bit_len = bit_len;
	return ret;
}

static inline void bit_free( bit_t *b ){
	free( b );
}

static inline bool bit_set( bit_t *b, uint16_t index ){
	if( index > b->bit_len )
		return false;
	//i-th block
	int i = index >> ELEM_BLOCK_SIZE_POWER_2; // (x / 64) <=> (x >> 6)
	//j-th bit in i-th block
	int j = index & (ELEM_BLOCK_SIZE - 1 );   // (x % 64) <=> (x & 63)
	b->data[i] |= (1ULL << j);
	return true;
}

static inline bool bit_get( bit_t *b, uint16_t index, bool *val ){
	if( index > b->bit_len )
		return false;

	int i = index >> ELEM_BLOCK_SIZE_POWER_2; // (x / 64) <=> (x >> 6)
	int j = index & ( ELEM_BLOCK_SIZE - 1 );  // (x % 64) <=> (x & 63)
	*val = (b->data[i] & (1ULL << j) );
	return true;
}
#endif /* SRC_LIB_BIT_H_ */
