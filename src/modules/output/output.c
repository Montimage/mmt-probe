/*
 * output.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */
#include <stdarg.h>

#include "../../configure.h"

#include "output.h"

#include "../../lib/memory.h"
#include "file/file_output.h"

#ifdef MONGODB_MODULE
	#include "mongodb/mongodb.h"
#endif

#ifdef REDIS_MODULE
	#include "redis/redis.h"
#endif

struct output_struct{
	uint16_t index;
	const char*input_src;
	uint32_t probe_id;
	struct timeval last_report_ts;
	const struct output_conf_struct *config;

	struct output_modules_struct{
		file_output_t *file;
#ifdef REDIS_MODULE
		redis_output_t *redis;
#endif

#ifdef KAFKA_MODULE

#endif

#ifdef MONGODB_MODULE
		mongodb_output_t *mongodb;
#endif
	}modules;
};


//public API
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src ){
	int i;
	if( ! config->is_enable )
		return NULL;

	output_t *ret = mmt_alloc_and_init_zero( sizeof( output_t ));
	ret->config = config;
	ret->index  = output_id;
	ret->input_src = input_src;
	ret->probe_id  = probe_id;

	if( ! ret->config->is_enable )
		return ret;

	if( ret->config->file->is_enable ){
		ret->modules.file = file_output_alloc_init( ret->config->file, output_id );
	}

#ifdef REDIS_MODULE
	if( ret->config->redis->is_enable )
		ret->modules.redis = redis_init( ret->config->redis );
#endif

#ifdef KAFKA_MODULE

#endif

#ifdef MONGODB_MODULE
	if( ret->config->mongodb->is_enable )
		ret->modules.mongodb = mongodb_output_alloc_init( ret->config->mongodb, ret->config->cache_max, output_id );
#endif

	return ret;
}


static inline int _write( output_t *output, output_channel_conf_t channels, const char *message ){
	int ret = 0;

	//put message inside an array: [message]
	if( output->config->format == OUTPUT_FORMAT_JSON  ){
		char new_msg[ MAX_LENGTH_REPORT_MESSAGE ];
		snprintf( new_msg, MAX_LENGTH_REPORT_MESSAGE, "[%s]", message );
		message = new_msg;
	}

	//output to file
	if( IS_ENABLE_OUTPUT_TO( FILE, channels )){
		file_output_write( output->modules.file, message );
		ret ++;
	}

#ifdef KAFKA_MODULE
	//output to Kafka
	if( output->config->kafka->is_enable && IS_ENABLE_OUTPUT_TO( KAFKA, channels )){
		ret ++;
	}
#endif

#ifdef REDIS_MODULE
	//output to redis
	if( output->modules.redis && IS_ENABLE_OUTPUT_TO( REDIS, channels )){
		ret += redis_send( output->modules.redis, message );
	}
#endif

#ifdef MONGODB_MODULE
	if( output->modules.mongodb && IS_ENABLE_OUTPUT_TO( MONGODB, channels )){

		//convert to JSON format
		if( output->config->format != OUTPUT_FORMAT_JSON  ){
				char new_msg[ MAX_LENGTH_REPORT_MESSAGE ];
				snprintf( new_msg, MAX_LENGTH_REPORT_MESSAGE, "[%s]", message );
				message = new_msg;
		}

		mongodb_output_write( output->modules.mongodb, message );
		ret ++;
	}
#endif

	return ret;
}

int output_write_report_with_format( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...){

	//global output is disable or no output on this channel
	if( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| IS_DISABLE_OUTPUT( channels ) )
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
					ts->tv_sec,
					ts->tv_usec);

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
int output_write( output_t *output, output_channel_conf_t channels, const char *message ){
	//global output is disable or no output on this channel
	if( ! output || ! output->config->is_enable || IS_DISABLE_OUTPUT(channels ))
		return 0;

	return _write( output, channels, message );
}

void output_flush( output_t *output ){
	if( !output )
		return;

	if( output->modules.file )
		file_output_flush( output->modules.file );

#ifdef MONGODB_MODULE
	if( output->modules.mongodb
			&& output->config->mongodb->is_enable )
		mongodb_output_flush_to_database( output->modules.mongodb );
#endif
}

void output_release( output_t * output){
	if( !output ) return;

	file_output_release( output->modules.file );

#ifdef MONGODB_MODULE
	mongodb_output_release( output->modules.mongodb );
#endif

	mmt_probe_free( output );
}
