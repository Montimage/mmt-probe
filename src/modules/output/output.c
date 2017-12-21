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
	struct timeval last_report_ts;
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
	ret->index          = worker_context->index;
	ret->last_report_ts.tv_sec  = 0;
	ret->last_report_ts.tv_usec = 0;
	ret->modules.file   = NULL;

	if( ! ret->config->is_enable )
		return ret;

	if( ret->config->file->is_enable ){
		ret->modules.file = file_output_alloc_init( ret->config->file, worker_context->index );
	}

#ifdef KAFKA_MODULE

#endif

	return ret;
}


int output_write_report( output_t *output, const output_channel_conf_t *channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...){

	//global output is disable or no output on this channel
	if( ! output->config->is_enable || ! channels->is_enable )
		return 0;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = snprintf( message, MAX_LENGTH_REPORT_MESSAGE, "%d,%d,\"%s\",%lu.%06lu,",
			report_type,
			output->worker_context->probe_context->config->probe_id,
			output->worker_context->probe_context->config->input->input_source,
			ts->tv_sec, ts->tv_usec);

	va_list args;

	va_start( args, format );
	offset += vsnprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, format, args);
	va_end( args );

	int ret = output_write( output, channels, message );
	output->last_report_ts.tv_sec  = ts->tv_sec;
	output->last_report_ts.tv_usec = ts->tv_usec;

	return ret;
}

//public API
int output_write( output_t *output, const output_channel_conf_t *channels, const char *message ){
	int ret = 0;
	//global output is disable or no output on this channel
	if( ! output->config->is_enable || ! channels->is_enable )
		return 0;

	//output to file
	if( output->config->file->is_enable && channels->is_output_to_file ){
		file_output_write( output->modules.file, message );
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
