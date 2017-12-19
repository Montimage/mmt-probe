/*
 * output.c
 *
 *  Created on: Dec 18, 2017
 *      Author: nhnghia
 */
#include <stdarg.h>

#include "../../lib/alloc.h"
#include "../../lib/configure.h"

#include "output.h"
#include "file/file_output.h"

struct output_struct{
	uint16_t index;
	const worker_context_t *worker_context;
	const struct output_conf_struct *config;

	struct output_modules_struct{
		file_output_t *file;
#ifdef REDIS_MODULE
#endif

#ifdef KAFKA_MODULE

#endif
	}modules;
};


//public API
output_t *output_alloc_init( const worker_context_t *worker_context ){
	output_t *ret = alloc( sizeof( output_t ));
	ret->worker_context = worker_context;
	ret->config         = &( worker_context->probe_context->config->outputs );
	ret->index          = 0;

	ret->modules.file   = NULL;

	if( ! ret->config->is_enable )
		return ret;



	if( ret->config->file->is_enable ){
		ret->modules.file = file_output_alloc_init( ret->config->file, worker_context->pid );
	}

#ifdef KAFKA_MODULE

#endif

	return ret;
}

//public API
int output_write( output_t *output, const output_channel_conf_t *channels, const char *format, ...){
	int ret = 0;
	//global output is disable or no output on this channel
	if( ! output->config->is_enable || ! channels->is_enable )
		return 0;

	char message[1];

	//output to file
	if( output->config->file->is_enable && channels->is_output_to_file ){
		va_list args;
		va_start( args, format );
		file_output_write( output->modules.file, format, args );
		va_end( args );
		ret ++;
	}

#ifdef KAFKA_MODULE
	//output to Kafka
	if( output->config->kafka->is_enable && channels->is_output_to_kafka ){
		ret ++;
	}
#endif

#ifdef REDIS_MODULE
	//output to redis
	if( output->config->redis->is_enable && channels->is_output_to_redis ){
		ret ++;
	}
#endif

	return ret;
}

void output_flush( output_t *output ){
	output->index ++;

	if( output->modules.file )
		file_output_flush( output->modules.file );
}

void output_release( output_t * output){
	if( output->modules.file )
		file_output_release( output->modules.file );
	xfree( output );
}
