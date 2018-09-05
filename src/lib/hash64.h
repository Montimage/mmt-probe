/*
 * hash64.h
 *
 *  Created on: Sep 5, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_SECURITY_HASH64_H_
#define SRC_MODULES_SECURITY_HASH64_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

/**
 * An hash table item
 */
typedef struct hash64_item_struct{
	uint64_t key;
	void *data;
}hash64_item_t;

/**
 * MMT Hash table
 */
typedef struct hash64_struct{
	uint32_t size;   //capacity of the table
	uint32_t count;  //number of real items inside table
	hash64_item_t items[];
}hash64_t;


/**
 * Create a new hash table
 * @param size
 */
static inline hash64_t* hash64_create( uint32_t size ){
	uint32_t i;
	hash64_t *ret = malloc( sizeof( hash64_t ) + sizeof( hash64_item_t ) * size );
	if( ret == NULL )
		return NULL;

	ret->size  = size;
	ret->count = 0;

	for( i=0; i<ret->size; i++ ){
		ret->items[i].key  = 0;
		ret->items[i].data = NULL;
	}
	return ret;
}

static inline void hash64_free( hash64_t *hash ){
	free( hash );
}

static inline bool hash64_is_full( hash64_t *hash ){
	return( hash->count >= hash->size );
}

/**
 * Add a new element to the hash table
 * @param hash
 * @param key
 * @param data
 * @return
 */
static inline uint32_t hash64_add( hash64_t *hash, uint64_t key, void *data ){
	uint32_t index   = key % hash->size;
	uint64_t counter = 0;

	//find an available slot
	while( hash->items[ index ].data != NULL ){
		//go to the next slot
		counter ++;
		index ++;

		if( counter >= hash->size )
			return hash->size;

		//return to zero if it goes over
		index %= hash->size;
	}
	hash->count ++;
	hash->items[ index ].key  = key;
	hash->items[ index ].data = data;
	return index;
}

/**
 * Search data by giving a key
 * @param hash
 * @param key
 */
static inline hash64_item_t* _hash64_get( hash64_t *hash, uint64_t key ){
	if( hash->count == 0 )
		return NULL;

	uint64_t index   = key % hash->size;
	uint64_t counter = 0;
	//find an available slot
	while( hash->items[ index ].data != NULL ){
		if( hash->items[ index ].key == key )
			return &hash->items[ index ];

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

static inline bool hash64_is_exist( hash64_t *hash, uint64_t key ){
	return (_hash64_get( hash, key ) != NULL );
}

static inline void* hash64_search( hash64_t *hash, uint64_t key ){
	hash64_item_t *item = _hash64_get( hash, key );
	if( item == NULL )
		return NULL;

	return item->data;
}

/**
 * Clear element having the key
 * @param hash
 * @param key
 * @return the data value of the key
 */
static inline void * hash64_remove( hash64_t *hash, uint64_t key ){
	hash64_item_t *item = _hash64_get( hash, key );
	if( item == NULL || item->data == NULL )
		return NULL;

	hash->count --;

	void *data = item->data;
	item->data = NULL;
	return data;
}

static inline void * hash64_remove_at_index( hash64_t *hash, uint32_t index ){
	if( index >= hash->size )
		return NULL;

	hash64_item_t *item = &hash->items[ index ];
	if( item->data == NULL  )
		return NULL;

	hash->count --;

	void *data = item->data;
	item->data = NULL;
	return data;
}

#endif /* SRC_MODULES_SECURITY_HASH64_H_ */
