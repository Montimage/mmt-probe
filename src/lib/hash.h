/*
 * hash.h
 *
 * This file implements a really simple hash table
 *
 *  Created on: Apr 4, 2022
 *      Author: nhnghia
 */

#ifndef SRC_LIB_HASH_H_
#define SRC_LIB_HASH_H_

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"

#define HASH_TABLE_SIZE 10000
/**
 * djb2 hash http://www.cse.yorku.ca/~oz/hash.html
 * @param str
 * @return
 */
static inline size_t djb2_hash_string(size_t len, const uint8_t *str){
	size_t hash = 5381;
	uint8_t c;
	size_t i;
	for( i=0; i<len; i++ ){
		c = str[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}


/**
 * An hash table item
 */
typedef struct hash_item_struct{
	bool is_occupy;
	size_t key_len;
	void *key;
	void *data;
}hash_item_t;

/**
 * MMT Hash table
 */
typedef struct hash_struct{
	size_t size;
	hash_item_t *items;
	size_t (*fn_hash_key)( size_t, const uint8_t * );
}hash_t;


/**
 * Create a new hash table
 * @param size
 */
static inline hash_t* hash_create(){
	size_t i;
	hash_t *ret = malloc( sizeof( hash_t ));
	ret->size  = HASH_TABLE_SIZE;
	ret->fn_hash_key = djb2_hash_string;
	ret->items = malloc( sizeof( hash_item_t ) * ret->size );
	for( i=0; i<ret->size; i++ ){
		ret->items[i].key  = NULL;
		ret->items[i].key_len = 0;
		ret->items[i].data = NULL;
		ret->items[i].is_occupy = false;
	}
	return ret;
}

static inline void hash_free( hash_t *hash ){
	if( hash ){
		free( hash->items);
		free( hash );
	}
}

/**
 * Add a new element to the hash table
 * @param hash
 * @param key
 * @param data
 * @return
 */
static inline bool hash_add( hash_t *hash, size_t key_len, uint8_t *key, void *data ){
	const uint64_t key_number = hash->fn_hash_key(key_len, key );
 	uint64_t index   = key_number % hash->size;
	uint64_t counter = 0;
	//find an available slot
	while( hash->items[ index ].is_occupy ){
		//go to the next slot
		counter ++;
		index ++;
		//fail if it goes over
		if( counter >= hash->size ){
			//TODO: increase table size
			log_write(LOG_ERR, "Hash table is full (size: %zu", hash->size );
			return false;
		}

		index %= hash->size;
	}
	hash->items[ index ].key_len   = key_len;
	hash->items[ index ].key       = key;
	hash->items[ index ].data      = data;
	hash->items[ index ].is_occupy = true;
	return true;
}

/**
 * Search data by giving a key
 * @param hash
 * @param key
 */
static inline void *hash_search( const hash_t *hash, size_t key_len, const uint8_t *key ){
	const uint64_t key_number = hash->fn_hash_key(key_len, key );
 	uint64_t index   = key_number % hash->size;
	uint64_t counter = 0;
	//find an available slot
	while( hash->items[ index ].is_occupy ){
		if( hash->items[ index ].key_len == key_len
		&& memcmp(key, hash->items[index].key, key_len) == 0 )
			return hash->items[ index ].data;

		//go to the next slot
		counter ++;
		index ++;

		//find all table but not found
		if( counter >= hash->size )
			return NULL;

		//return to zero if it goes over
		index %= hash->size;
	}
	return NULL;
}


#endif /* SRC_LIB_HASH_H_ */
