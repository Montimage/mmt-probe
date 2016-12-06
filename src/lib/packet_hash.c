/*
 * packet_hash.c
 *
 *  Created on: 14 avr. 2016
 *      Author: nhnghia
 */

#include <stdlib.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "packet_hash.h"
#include "optimization.h"

#define __HASH_TABLE_SIZE 100000



uint32_t _get_index( uint32_t nu ){
	static uint32_t hash_table[ __HASH_TABLE_SIZE ];
	static uint32_t length = 0;
	static uint32_t i, cache_index = 0;

	if( hash_table[ cache_index ] == nu ) return cache_index;

	//check if this number exists in the hash table
	for( i=0; i<length; i++ )
		if( hash_table[i] == nu ){
			cache_index = i;
			return i;
		}

	//if not, add it
	hash_table[ length ] = nu;
	cache_index = length;

	length ++;

	if( unlikely( length >= __HASH_TABLE_SIZE ))
		length = 0;

	return cache_index;
}



