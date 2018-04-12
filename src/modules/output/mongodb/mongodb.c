/*
 * mongodb.c
 *
 *  Created on: Apr 11, 2018
 *          by: Huu Nghia Nguyen
 */

#include <bcon.h>
#include <mongoc.h>
#include <pthread.h>

#include "mongodb.h"
#include "../../../lib/memory.h"

struct mongodb_output_struct{
	uint16_t client_id;
	mongoc_collection_t *mongo_collection;
	mongoc_client_t     *mongo_client;

	bson_t **messages_cache;

	uint32_t messages_cache_size_limit;
	uint32_t messages_count;
};


static pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;

mongodb_output_t* mongodb_output_alloc_init( const mongodb_output_conf_t*config, uint32_t cache_size,  uint16_t id ){
	mongoc_client_t *client;
	mongoc_collection_t *collection;

	bson_error_t error;
	bson_t *bson_command;
	int i;
	static bool is_first_times = true;

	char connection_string[ 1000 ];



	//Register also the application name so we can track it in the profile logs on the server.
	snprintf( connection_string, sizeof( connection_string), "mongodb://%s:%d/?appname=mmt-probe-%d",
			config->host.host_name, config->host.port_number, id );

	pthread_mutex_lock( &lock_mutex );
	//call only one time in multi-threading in the first output
	if( is_first_times )
		mongoc_init();

	client = mongoc_client_new ( connection_string );

	if( client == NULL ){
		log_write( LOG_ERR, "Cannot create mongodb client" );
		abort();
	}

	collection = mongoc_client_get_collection( client, config->database_name, config->collection_name );

	if( is_first_times ){
		//empty the collection
		//if not empty: the collection can be capped ???
		if( !mongoc_collection_drop_with_opts(collection, NULL, &error ) )
			log_write( LOG_WARNING, "Cannot empty collection '%s'. Error: %s",
					config->collection_name, error.message );

		//convert the collection to capped-collection to limit its size and its number of documents
		if( config->limit_size != 0 ){
			//mongodb command to convert
			bson_command = BCON_NEW ("convertToCapped", BCON_UTF8 ( config->collection_name ),
					"size", BCON_INT32( config->limit_size));

			if ( ! mongoc_collection_command_simple( collection, bson_command, NULL, NULL, &error ))
				log_write( LOG_WARNING, "Cannot convert '%s' to crapped-collection, thus the limits will not work. Error: %s",
						config->collection_name, error.message );
			bson_destroy( bson_command );
		}
	}
	pthread_mutex_unlock(&lock_mutex);


	mongodb_output_t *ret = mmt_alloc( sizeof( mongodb_output_t) );
	ret->mongo_collection = collection;
	ret->mongo_client     = client;

	ret->messages_cache_size_limit = cache_size;
	ret->messages_count = 0;
	//allocate cache for a list of bson documents
	ret->messages_cache = mmt_alloc( sizeof( bson_t *) * ret->messages_cache_size_limit );
	//initialize each element of the cache
	for( i=0; i<ret->messages_cache_size_limit; i++ )
		ret->messages_cache[i] = bson_new();

	is_first_times = false;

	return ret;
}

void mongodb_output_flush_to_database( mongodb_output_t *mongo ){
	bson_error_t error;

	if( mongo == NULL || mongo->messages_count == 0 )
		return;

	if( ! mongoc_collection_insert_many( mongo->mongo_collection,
			(const bson_t **)mongo->messages_cache,
			mongo->messages_count,
			NULL,
			NULL,
			&error)){
			log_write( LOG_ERR, "Error when send message to mongodb: %s", error.message );
	}

	//reset cache to zero
	mongo->messages_count = 0;
}

int mongodb_output_write( mongodb_output_t *mongo, const char *message ){
	bson_error_t error;

	//convert to bson
	bson_t *bson = mongo->messages_cache[ mongo->messages_count ];

	if( ! bson_init_from_json( bson, message, -1, &error ) ){
		log_write( LOG_ERR, "Message is not well formatted for MongoDB: %s", error.message );
		return 0;
	}

	mongo->messages_count ++;

	if( mongo->messages_count >= mongo->messages_cache_size_limit )
		mongodb_output_flush_to_database( mongo );

	return 1;
}

void mongodb_output_release( mongodb_output_t *mongo ){
	static bool is_first_times = true;
	int i;
	for( i=0; i<mongo->messages_cache_size_limit; i++ )
		bson_destroy( mongo->messages_cache[i] );

	mongoc_collection_destroy( mongo->mongo_collection );
	mongoc_client_destroy (mongo->mongo_client);

	//call only one time in multi-threading
	pthread_mutex_lock( &lock_mutex );
	if( is_first_times ){
		mongoc_cleanup ();
		is_first_times = false;
	}
	pthread_mutex_unlock( &lock_mutex );

	mmt_probe_free( mongo->messages_cache );
	mmt_probe_free( mongo );
}
