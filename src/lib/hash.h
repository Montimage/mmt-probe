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
#include <stdbool.h>

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
	size_t (*fn_hash_key)( size_t, const void* );
} hash_t;

/**
 * Clean all items in the hash table.
 * Before calling this function,
 *  you might need to call "hash_visit" function to visit each item and free its key and data.
 * @param hash
 */
void hash_clean( hash_t *hash );


/**
 * Create a new hash table
 */
hash_t* hash_create_with_init_capability( size_t init_capab);


hash_t* hash_create();


void hash_free( hash_t *hash );

void hash_visit( hash_t *hash, void (*callback)(size_t key_len, void *key, void *data, void *args), void *args );

/**
 * Add a new element to the hash table
 * @param hash
 * @param key
 * @param data
 * @return
 */
bool hash_add( hash_t *hash, size_t key_len, void *key, void *data );

/**
 * Search data by giving a key
 * @param hash
 * @param key
 */
void *hash_search( const hash_t *hash, size_t key_len, const void *key );


#endif /* SRC_LIB_HASH_H_ */
