/*
 * output.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */
#include <stdarg.h>

#include "../../lib/alloc.h"
#include "../../lib/configure.h"

#include "output.h"
#include "file/file_output.h"

struct output_struct{
	uint16_t index;
	const char*input_src;
	uint32_t probe_id;
	struct timeval last_report_ts;
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
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src ){
	if( ! config->is_enable )
		return NULL;

	output_t *ret = alloc( sizeof( output_t ));
	ret->config = config;
	ret->index  = output_id;
	ret->last_report_ts.tv_sec  = 0;
	ret->last_report_ts.tv_usec = 0;
	ret->modules.file   = NULL;
	ret->input_src = input_src;
	ret->probe_id  = probe_id;

	if( ! ret->config->is_enable )
		return ret;

	if( ret->config->file->is_enable ){
		ret->modules.file = file_output_alloc_init( ret->config->file, output_id );
	}

#ifdef KAFKA_MODULE

#endif

	return ret;
}


static inline int _write( output_t *output, const output_channel_conf_t *channels, const char *message ){
	int ret = 0;

	//output to file
	if( output->config->file->is_enable && (channels == NULL || channels->is_output_to_file )){
		file_output_write( output->modules.file, message );
		ret ++;
	}

#ifdef KAFKA_MODULE
	//output to Kafka
	if( output->config->kafka->is_enable && (channels == NULL || channels->is_output_to_kafka )){
		ret ++;
	}
#endif

#ifdef REDIS_MODULE
	//output to redis
	if( output->config->redis->is_enable && (channels == NULL || channels->is_output_to_redis )){
		ret ++;
	}
#endif

	return ret;
}

int output_write_report( output_t *output, const output_channel_conf_t *channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...){

	//global output is disable or no output on this channel
	if( unlikely( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| (channels != NULL && ! channels->is_enable ) ))
		return 0;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];

	if( unlikely( format == NULL )){
		snprintf( message, MAX_LENGTH_REPORT_MESSAGE, "%d,%"PRIu32",\"%s\",%lu.%06lu",
			report_type,
			output->probe_id,
			output->input_src,
			ts->tv_sec, ts->tv_usec );
	} else {
		int offset = snprintf( message, MAX_LENGTH_REPORT_MESSAGE, "%d,%"PRIu32",\"%s\",%lu.%06lu,",
					report_type,
					output->probe_id,
					output->input_src,
					ts->tv_sec, ts->tv_usec);
		va_list args;

		va_start( args, format );
		offset += vsnprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, format, args);
		va_end( args );
	}

	int ret = _write( output, channels, message );
	output->last_report_ts.tv_sec  = ts->tv_sec;
	output->last_report_ts.tv_usec = ts->tv_usec;

	return ret;
}

//public API
int output_write( output_t *output, const output_channel_conf_t *channels, const char *message ){
	//global output is disable or no output on this channel
	if( ! output || ! output->config->is_enable || (channels && ! channels->is_enable ))
		return 0;

	return _write( output, channels, message );
}

void output_flush( output_t *output ){
	if( !output )
		return;

	if( output->modules.file )
		file_output_flush( output->modules.file );
}

void output_release( output_t * output){
	if( !output ) return;

	if( output->modules.file )
		file_output_release( output->modules.file );
	xfree( output );
}
