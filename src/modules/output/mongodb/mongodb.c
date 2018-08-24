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
#include "../../../lib/malloc.h"

struct mongodb_output_struct{
	uint32_t messages_max_limit;
	uint32_t messages_count;

	bson_t **messages_cache;
	mongoc_collection_t *mongo_collection;
	mongoc_client_t *mongo_client; //we need to maintain this to maintain the connection to DB server
};


static pthread_mutex_t lock_mutex = PTHREAD_MUTEX_INITIALIZER;

mongodb_output_t* mongodb_output_alloc_init( const mongodb_output_conf_t*config, uint32_t cache_max,  uint16_t id ){
	mongoc_client_t *mongo_client;
	mongoc_database_t *mongo_db;
	mongoc_collection_t *mongo_collection;

	bson_error_t bson_err;
	bson_t bson_reply;
	bson_t *bson_cmd;
	bson_iter_t bson_iter, bson_iter_tmp;

	int i;
	//flag to execute only one time in case the function is used in multi-threading
	static bool is_first_times = true;
	char connection_string[ 1000 ];

	if( ! config->is_enable )
		return NULL;

	//Register also the application name so we can track it in the profile logs on the server.
	snprintf( connection_string, sizeof( connection_string), "mongodb://%s:%d/?appname=mmt-probe-%d",
			config->host.host_name, config->host.port_number, id );

	pthread_mutex_lock( &lock_mutex );

	//call only one time in multi-threading in the first output
	if( is_first_times )
		mongoc_init();

	mongo_client = mongoc_client_new ( connection_string );

	if( mongo_client == NULL )
		ABORT( "Cannot create mongodb client" );

	mongo_db = mongoc_client_get_database (mongo_client, config->database_name);

	//check if collection does not exist
	if( ! mongoc_database_has_collection( mongo_db,  config->collection_name, &bson_err)){
		//collection does not exist => create a new one
		mongo_collection = mongoc_database_create_collection( mongo_db, config->collection_name, NULL, &bson_err );
		if( mongo_collection == NULL )
			ABORT("Cannot create collection [%s] in mongodb [%s]. Error: %s",
					config->collection_name, config->database_name, bson_err.message );
	}
	else
		mongo_collection = mongoc_client_get_collection( mongo_client, config->database_name, config->collection_name );

	//we need to do this only one times for all threads
	if( is_first_times ){

		//convert the collection to capped-collection to limit its size and its number of documents
		if( config->limit_size != 0 ){
			//mongodb command to convert
			bson_cmd = BCON_NEW ("convertToCapped", BCON_UTF8 ( config->collection_name ),
					"size", BCON_INT32( config->limit_size * 1000 * 1000));

			if ( ! mongoc_collection_command_simple( mongo_collection, bson_cmd, NULL, NULL, &bson_err ))
				log_write( LOG_WARNING, "Cannot convert [%s] to crapped-collection, thus the limit-size will not work. Error: %s",
						config->collection_name, bson_err.message );

			bson_destroy( bson_cmd );
		}else{
			//convert a capped collection to normal one to eliminate the limit-size
			bool is_capped = false;
			//check if the collection is capped??
			if( mongoc_collection_stats(mongo_collection, NULL, &bson_reply, &bson_err)) {
				//find "capped" field in bson_reply
				if( bson_iter_init (&bson_iter, &bson_reply) && bson_iter_find_descendant (&bson_iter, "capped", &bson_iter_tmp) ) {
					is_capped = bson_iter_as_bool( &bson_iter );
					if( is_capped )
						log_write( LOG_INFO, "Collection [%s] is capped", config->collection_name );
				}
			} else
				log_write( LOG_WARNING, "Cannot execute collStats command: %s", bson_err.message);

			bson_destroy( &bson_reply );

			//as collection is capped => its size is limited
			//we need to convert it to normal collection by: (1) rename the current collection, (2) copy to a new normal one, (3) drop current one
			if( is_capped ){
				//(1) rename
				const char *tmp_collection_name = "___tmp_capped";
				if( ! mongoc_collection_rename(mongo_collection, NULL, tmp_collection_name, false, &bson_err ) )
					log_write( LOG_WARNING, "Cannot rename collection [%s] to [%s]. Error: %s",
							config->collection_name, tmp_collection_name, bson_err.message );
				else{
					//(2) copy content to normal one using aggregate
					bson_cmd = BCON_NEW ("pipeline",
							"[", "{","$match", "{", "}", "}",
								 "{", "$out", BCON_UTF8 ( tmp_collection_name ), "}",
							"]");
					if( !mongoc_collection_aggregate(mongo_collection, MONGOC_QUERY_NONE, bson_cmd, NULL, NULL) )
						log_write( LOG_WARNING, "Cannot copy data to new collection '%s'. Error: %s",
								config->collection_name, bson_err.message );

					bson_destroy( bson_cmd );

					//(3): drop
					if( ! mongoc_collection_drop(mongo_collection, &bson_err ) )
						log_write( LOG_WARNING, "Cannot empty collection '%s'. Error: %s",
								config->collection_name, bson_err.message );

					//re-point collection to correct one
					mongoc_collection_destroy( mongo_collection );

					mongo_collection = mongoc_client_get_collection( mongo_client, config->database_name, config->collection_name );
				}
			}
		}
	}

	mongoc_database_destroy( mongo_db );
	pthread_mutex_unlock(&lock_mutex);


	mongodb_output_t *ret = mmt_alloc( sizeof( mongodb_output_t) );
	ret->mongo_collection = mongo_collection;
	ret->mongo_client     = mongo_client; //even it does not appear in code but we need to maintain it to conserve the connection to server
	ret->messages_max_limit = cache_max;
	ret->messages_count = 0;
	//allocate cache for a list of bson documents
	ret->messages_cache = mmt_alloc( sizeof( bson_t *) * ret->messages_max_limit );
	//initialize each element of the cache
	for( i=0; i<ret->messages_max_limit; i++ )
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
	int i;
	for( i=0; i<mongo->messages_count; i++ )
		bson_destroy( mongo->messages_cache[i] );

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

	if( mongo->messages_count >= mongo->messages_max_limit )
		mongodb_output_flush_to_database( mongo );

	return 1;
}

void mongodb_output_release( mongodb_output_t *mongo ){
	static bool is_first_times = true;
	int i;
	if( mongo == NULL )
		return;

	mongodb_output_flush_to_database( mongo );

	for( i=0; i<mongo->messages_max_limit; i++ ){
		bson_free( mongo->messages_cache[i] );
	}
	mmt_probe_free( mongo->messages_cache );

	mongoc_collection_destroy( mongo->mongo_collection );
	mongoc_client_destroy( mongo->mongo_client );

	//call only one time in multi-threading
	pthread_mutex_lock( &lock_mutex );
	if( is_first_times ){
		mongoc_cleanup ();
		is_first_times = false;
	}
	pthread_mutex_unlock( &lock_mutex );


	mmt_probe_free( mongo );
}
