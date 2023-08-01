/*
 * output.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */
#include <stdarg.h>
#include <pthread.h>

#include "../../configure.h"

#include "output.h"

#include "../../lib/string_builder.h"
#include "../../lib/malloc.h"
#include "../../lib/memory.h"
#include "file/file_output.h"
#include "kafka/kafka_output.h"
#include "socket/socket_output.h"
#include "mongodb/mongodb.h"
#include "redis/redis.h"

struct output_struct{
	uint16_t index;
	uint32_t probe_id;
	const char*input_src;
	struct timeval last_report_ts;
	const struct output_conf_struct *config;

	//mutex is used only in multi-threading output
	pthread_mutex_t *mutex;

	struct output_modules_struct{
		file_output_t *file;
		IF_ENABLE_REDIS(   redis_output_t *redis; )
		IF_ENABLE_KAFKA(   kafka_output_t *kafka; )
		IF_ENABLE_MONGODB( mongodb_output_t *mongodb; )
		IF_ENABLE_SOCKET(  socket_output_t *socket; )
	}modules;
};


//public API
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src, bool is_multi_threads ){
	int i;
	if( ! config->is_enable )
		return NULL;

	output_t *ret  = mmt_alloc_and_init_zero( sizeof( output_t ));
	ret->config    = config;
	ret->index     = output_id;
	ret->input_src = input_src;
	ret->probe_id  = probe_id;

	//When using output in multi-threads, we need to synchronize their function calls by mutex
	if( is_multi_threads ){
		ret->mutex = malloc( sizeof(pthread_mutex_t) );
		pthread_mutex_init(ret->mutex, NULL);
	}else
		ret->mutex = NULL;

	if( ! ret->config->is_enable )
		return ret;


	/*
	 * Initialize the output channels
	 * The result must be NULL if output is disable to its channel,
	 * for example: ret->modules.file must be NULL if file-output.enable=false
	 */

	ret->modules.file = file_output_alloc_init( ret->config->file, output_id );

#ifdef REDIS_MODULE
	ret->modules.redis = redis_init( ret->config->redis );
#endif

#ifdef KAFKA_MODULE
	ret->modules.kafka = kafka_output_init( ret->config->kafka );
#endif

#ifdef MONGODB_MODULE
	ret->modules.mongodb = mongodb_output_alloc_init( ret->config->mongodb, ret->config->cache_max, output_id );
#endif

#ifdef SOCKET_MODULE
	ret->modules.socket = socket_output_init( ret->config->socket );
#endif
	return ret;
}

/**
 * Write an entire report to output channels
 * @param output
 * @param channels
 * @param message
 * @return
 */
static inline int _write( output_t *output, output_channel_conf_t channels, const char *message, bool raw ){
	int ret = 0;
	char new_msg[ MAX_LENGTH_REPORT_MESSAGE ];

	//we surround message inside [] to convert it to JSON
	//this needs to be done when:
	//- output format is JSON,
	//- or when we need to output to MongoDB
	if( (output->config->format == OUTPUT_FORMAT_JSON && !raw)
#ifdef MONGODB_MODULE
			|| (output->modules.mongodb && IS_ENABLE_OUTPUT_TO( MONGODB, channels ) )
#endif
			){

		//surround message by [ and ]
		new_msg[0] = '[';
		size_t len = strlen( message );
		memcpy( new_msg + 1, message, len );
		new_msg[ len+1 ] = ']';
		new_msg[ len+2 ] = '\0';

		//use new_msg when output format is JSON
		if( output->config->format == OUTPUT_FORMAT_JSON )
			message = new_msg;
	}
	//output to stdout
	if( IS_ENABLE_OUTPUT_TO( STDOUT, channels) ){
		fprintf( stdout, "%s\n", message );
		ret ++;
	}
	//output to file
	if( IS_ENABLE_OUTPUT_TO( FILE, channels )){
		file_output_write( output->modules.file, message );
		ret ++;
	}

#ifdef KAFKA_MODULE
	//output to Kafka
	if( output->modules.kafka && IS_ENABLE_OUTPUT_TO( KAFKA, channels )){
		ret += kafka_output_send( output->modules.kafka, message );
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
		//here we output new_msg (not message)
		mongodb_output_write( output->modules.mongodb, new_msg );
		ret ++;
	}
#endif

#ifdef SOCKET_MODULE
	if( output->modules.socket && IS_ENABLE_OUTPUT_TO( SOCKET, channels )){
		ret += socket_output_send( output->modules.socket, message );
	}
#endif
	return ret;
}


/*
 * This macro is used to synchronize only when using in multi-threading,
 * i.e., (output->mutex != NULL)
 * The code after calling this macro is ensured thread-safe.
 * __UNLOCK macro must be called before any return.
 *
 * Currently we need to lock only when security is enable.
 */
#define __LOCK_IF_NEED( output )                        \
	while( output->mutex != NULL &&                     \
		pthread_mutex_lock( output->mutex ) != 0 );     \
/*
 * This macro unlocks the mutex being locked by the macro above.
 */
#define __UNLOCK_IF_NEED( output )                      \
	while( output->mutex != NULL &&                     \
		pthread_mutex_unlock( output->mutex ) != 0 );   \


//public API
int output_write_report( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* message_body){

	__LOCK_IF_NEED( output );

	//global output is disable or no output on this channel
	if( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| IS_DISABLE_OUTPUT( channels ) ){
		__UNLOCK_IF_NEED( output );
		return 0;
	}

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;
	STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( report_type ),
			__INT( output->probe_id ),
			__STR( output->input_src ),
			__TIME( ts )
	);

	if( message_body != NULL ){
		message[ offset ++ ] = ',';
		size_t len = strlen( message_body );
		if( len > MAX_LENGTH_REPORT_MESSAGE - offset )
			len = MAX_LENGTH_REPORT_MESSAGE - offset;
		memcpy( message+offset, message_body, len );
		message[ offset + len ] = '\0';
	}

	int ret = _write( output, channels, message, false );
	output->last_report_ts.tv_sec  = ts->tv_sec;
	output->last_report_ts.tv_usec = ts->tv_usec;

	__UNLOCK_IF_NEED( output );
	return ret;
}

//public API
int output_write_report_with_format( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...){

	__LOCK_IF_NEED( output );
	//global output is disable or no output on this channel
	if( output == NULL
			|| output->config == NULL
			|| ! output->config->is_enable
			|| IS_DISABLE_OUTPUT( channels ) ){
		__UNLOCK_IF_NEED( output );
		return 0;
	}
	//we need to unlock here as hereafter are thread-safe
	//otherwise there will be a deadlock as there will be a lock in @output_write_report
	__UNLOCK_IF_NEED( output );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset, ret;

	if( unlikely( format == NULL )){
		ret = output_write_report( output, channels, report_type, ts, NULL);
	} else {
		va_list args;
		offset = 0;
		va_start( args, format );
		offset += vsnprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, format, args);
		va_end( args );

		message[ offset ] = '\0'; //well null-terminated
		ret = output_write_report( output, channels, report_type, ts, message );
	}

	return ret;
}

//public API
int output_write( output_t *output, output_channel_conf_t channels, const char *message ){
	int ret;
	__LOCK_IF_NEED( output );

	//global output is disable or no output on this channel
	if( ! output || ! output->config->is_enable || IS_DISABLE_OUTPUT(channels ))
		ret = 0;
	else
		ret = _write( output, channels, message, true );

	__UNLOCK_IF_NEED( output );
	return ret;
}

//public API
void output_flush( output_t *output ){
	if( !output )
		return;

	__LOCK_IF_NEED( output );

	if( output->modules.file )
		file_output_flush( output->modules.file );

	fflush(stdout);

#ifdef MONGODB_MODULE
	if( output->modules.mongodb
			&& output->config->mongodb->is_enable )
		mongodb_output_flush_to_database( output->modules.mongodb );
#endif

	__UNLOCK_IF_NEED( output );
}

//public API
void output_release( output_t * output){
	if( !output ) return;

	fflush(stdout);
	file_output_release( output->modules.file );

	IF_ENABLE_MONGODB( mongodb_output_release( output->modules.mongodb ); )
	IF_ENABLE_KAFKA( kafka_output_release( output->modules.kafka ); )
	IF_ENABLE_REDIS( redis_release( output->modules.redis ); )
	IF_ENABLE_SOCKET( socket_output_release( output->modules.socket ); )

	if( output->mutex ){
		pthread_mutex_destroy( output->mutex );
		mmt_probe_free( output->mutex );
	}
	mmt_probe_free( output );
}
