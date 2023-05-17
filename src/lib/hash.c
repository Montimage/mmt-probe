/*
 * hash.h
 *
 * This file implements a really simple hash table
 *
 *  Created on: Apr 4, 2022
 *      Author: nhnghia
 */

#include <stdint.h>
#include <stdlib.h>

#include "hash.h"
#include "log.h"

#define HASH_TABLE_INITIAL_CAPABILITY 1024
/**
 * djb2 hash http://www.cse.yorku.ca/~oz/hash.html
 * @param str
 * @return
 */
static size_t _djb2_hash_string(size_t len, const void *str){
	size_t hash = 5381;
	uint8_t c;
	size_t i;
	const uint8_t *s = str;
	for( i=0; i<len; i++ ){
		c = s[i];
		hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
	}

	return hash;
}


/**
 * Clean all items in the hash table.
 * Before calling this function,
 *  you might need to call "hash_visit" function to visit each item and free its key and data.
 * @param hash
 */
void hash_clean( hash_t *hash ){
	size_t i;
	for( i=0; i<hash->capability; i++ ){
		hash->items[i].key  = NULL;
		hash->items[i].key_len = 0;
		hash->items[i].data = NULL;
		hash->items[i].is_occupy = false;
	}
}


/**
 * Create a new hash table
 */
hash_t* hash_create_with_init_capability( size_t init_capab){
	size_t i;
	hash_t *ret = malloc( sizeof( hash_t ));
	ret->capability  = init_capab;
	ret->fn_hash_key = _djb2_hash_string;
	ret->items = calloc( ret->capability, sizeof( hash_item_t ) );
	hash_clean( ret );
	return ret;
}


hash_t* hash_create(){
	return hash_create_with_init_capability( HASH_TABLE_INITIAL_CAPABILITY );
}


void hash_free( hash_t *hash ){
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
static void _hash_increase_capability( hash_t *hash ){
	size_t i;
	hash_item_t *old_items, *item;
	size_t old_capability = hash->capability;
	old_items = hash->items;

	//double the capability
	hash->capability *= 2;

	//init new array of items
	hash->items = calloc( hash->capability, sizeof( hash_item_t ) );
	hash_clean( hash );

	//copy the items from the old table to the new one
	for( i=0; i<old_capability; i++ ){
		item = &old_items[i];
		//this item is empty
		if( ! item->is_occupy )
			continue;

		//add the item into new hash
		hash_add( hash, item->key_len, item->key, item->data );
	}

	//free the old table
	free( old_items);
}

void hash_visit( hash_t *hash, void (*callback)(size_t key_len, void *key, void *data, void *args), void *args ){
	size_t i;
	const hash_item_t *item;
	for( i=0; i<hash->capability; i++ ){
		item = &hash->items[i];
		if( item->is_occupy )
			callback( item->key_len, item->key, item->data, args );
	}
}


/**
 * Add a new element to the hash table
 * @param hash
 * @param key
 * @param data
 * @return
 */
bool hash_add( hash_t *hash, size_t key_len, void *key, void *data ){
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
			_hash_increase_capability( hash );

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
void *hash_search( const hash_t *hash, size_t key_len, const void *key ){
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
