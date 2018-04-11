/*
 * mongodb.c
 *
 *  Created on: Apr 11, 2018
 *          by: Huu Nghia Nguyen
 */

#include <mongoc.h>

#include "mongodb.h"
#include "../../../lib/memory.h"

struct mongodb_output_struct{
	uint16_t client_id;
	mongoc_collection_t *mongo_collection;
	mongoc_client_t     *mongo_client;
};

mongodb_output_t* mongodb_output_alloc_init( const mongodb_output_conf_t*config,  uint16_t id ){
	mongoc_client_t *client;
	mongoc_collection_t *collection;

	bson_error_t error;
	bson_t *bson_command;

	bool is_first_outputor = ( id == 0 );

	char connection_string[ 1000 ];
	//Register also the application name so we can track it in the profile logs on the server.
	snprintf( connection_string, sizeof( connection_string), "mongodb://%s:%d/?appname=mmt-probe-%d",
			config->host.host_name, config->host.port_number, id );

	//call only one time in multi-threading in the first output
	if( is_first_outputor )
		mongoc_init();

	client = mongoc_client_new ( connection_string );

	if( client == NULL ){
		log_write( LOG_ERR, "Cannot create mongodb client" );
		abort();
	}

	collection = mongoc_client_get_collection( client, config->database_name, config->collection_name );

	if( is_first_outputor ){
		//empty the collection
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

	mongodb_output_t *ret = mmt_alloc( sizeof( mongodb_output_t) );
	ret->mongo_collection = collection;
	ret->mongo_client     = client;
	return ret;
}

int mongodb_output_write( mongodb_output_t *mongo, const char *message ){
	bson_error_t error;

	//convert to bson
	bson_t *bson_insert = bson_new_from_json( (uint8_t *) message, -1, &error );
	if( bson_insert == NULL ){
		log_write( LOG_ERR, "Message is not well formatted: %s", error.message );
		return 0;
	}

	//insert to DB
	if( !mongoc_collection_insert( mongo->mongo_collection, MONGOC_INSERT_NONE, bson_insert, NULL, &error)) {
		bson_destroy( bson_insert );
		log_write( LOG_ERR, "Error when send message to mongodb: %s", error.message );
		return 0;
	}
	bson_destroy( bson_insert );

	return 1;
}

void mongodb_output_release( mongodb_output_t *mongo ){
	mongoc_collection_destroy( mongo->mongo_collection );
	mongoc_client_destroy (mongo->mongo_client);

	//call only one time in multi-threading
	if( mongo->client_id == 0 )
		mongoc_cleanup ();
	mmt_probe_free( mongo );
}
