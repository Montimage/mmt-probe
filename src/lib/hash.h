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

#define HASH_TABLE_INITIAL_CAPABILITY 1024
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
} hash_item_t;

/**
 * MMT Hash table
 */
typedef struct hash_struct{
	size_t capability;   //current capability of the hash
	hash_item_t *items; //list of item
	size_t (*fn_hash_key)( size_t, const uint8_t * );
} hash_t;



/**
 * Create a new hash table
 */
static inline hash_t* hash_create(){
	size_t i;
	hash_t *ret = malloc( sizeof( hash_t ));
	ret->capability  = HASH_TABLE_INITIAL_CAPABILITY;
	ret->fn_hash_key = djb2_hash_string;
	ret->items = malloc( sizeof( hash_item_t ) * ret->capability );
	for( i=0; i<ret->capability; i++ ){
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
 * Create a new hash table within a new capability
 * @param hash
 * @param new_capability
 * @return a new hash table containing all data from the old table
 */
static inline void hash_increase_capability( hash_t *hash ){
	size_t i;
	const hash_item_t *old_items, *item;
	size_t old_capability = hash->capability;
	old_items = hash->items;

	//double the capability
	hash->capability *= 2;

	//init new array of items
	hash->items = malloc( sizeof( hash_item_t ) * hash->capability );
	for( i=0; i<hash->capability; i++ ){
		hash->items[i].key  = NULL;
		hash->items[i].key_len = 0;
		hash->items[i].data = NULL;
		hash->items[i].is_occupy = false;
	}

	//copy the items from the old table to the new one
	for( i=0; i<old_capability; i++ ){
		item = old_items[i];
		//this item is empty
		if( ! item->is_occupy )
			continue;

		//add the item into new hash
		hash_add( hash, item->key_len, item->key );
	}

	//free the old table
	free( old_items);
}
/**
 * Add a new element to the hash table
 * @param hash
 * @param key
 * @param data
 * @return
 */
static inline bool hash_add( hash_t *hash, size_t key_len, uint8_t *key, void *data ){
	const size_t key_number = hash->fn_hash_key(key_len, key );
 	size_t index   = key_number % hash->capability;
	size_t counter = 0;
	//find an available slot
	while( hash->items[ index ].is_occupy ){
		//go to the next slot
		counter ++;
		index ++;

		// if we visited all items of the table, but none of them is available
		// => we need to increase the table capability
		if( counter >= hash->capability ){
			log_write(LOG_WARNING, "Hash table is full (capability: %zu)", hash->capability );
			hash_increase_capability( hash );

			//recalculate index as the hash's capability changed
			index = key_number % hash->capability;
			counter = 0;
		}

		//repeat
		if( index >= hash->capability )
			index = 0;
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
	const size_t key_number = hash->fn_hash_key(key_len, key );
 	size_t index   = key_number % hash->capability;
	size_t counter = 0;
	//find an available slot
	while( hash->items[ index ].is_occupy ){
		if( hash->items[ index ].key_len == key_len
		&& memcmp(key, hash->items[index].key, key_len) == 0 )
			return hash->items[ index ].data;

		//go to the next slot
		counter ++;
		index ++;

		//find all table but not found
		if( counter >= hash->capability )
			return NULL;

		//return to zero if it goes over
		if( index >= hash->capability )
			index = 0;
	}
	return NULL;
}


#endif /* SRC_LIB_HASH_H_ */
