/*
 * file_output.c
 *
 *  Created on: Dec 19, 2017
 *      Author: nhnghia
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "../../../lib/alloc.h"
#include "file_output.h"

#include "../../../lib/limit.h"

struct file_output_struct{
	uint16_t id;
	time_t created_time_of_file;

	FILE *file;
	const file_output_conf_t *config;
};

static inline void _create_new_file( file_output_t *output ){
	char filename[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	//create output file
	output->created_time_of_file = time( 0 );
	snprintf( filename, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%lu_%d_%s",
			output->config->directory,
			output->created_time_of_file,
			output->id,
			output->config->filename );
	output->file = fopen( filename,"w");

	if( output->file == NULL )
		log_write( LOG_ERR, "Cannot create data file %s", filename );

}

file_output_t* file_output_alloc_init( const file_output_conf_t *config, uint16_t id ){
	if( config->is_enable == false )
		return NULL;

	file_output_t *ret = alloc( sizeof( file_output_t) );
	ret->file = NULL;
	ret->config = config;
	ret->id     = id;

	//init file, created_time_of_file
	_create_new_file( ret );
	return ret;
}


static inline void _create_semaphore_file_if_need( file_output_t *output ){
	if( output && output->file && output->config->is_sampled ){
		char filename[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

		//create semaphore
		snprintf( filename, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%lu_%d_%s.sem",
				output->config->directory,
				output->created_time_of_file,
				output->id,
				output->config->filename );
		FILE *file = fopen( filename,"w");
		if( file == NULL )
			log_write( LOG_ERR, "Cannot create semaphore file %s", filename );
		else
			fclose( file );
	}
}


void file_output_flush( file_output_t * output){
	if( unlikely( output == NULL ))
		return;

	if( output->file ){
		fflush( output->file );

		if( output->config->is_sampled )
			fclose( output->file );
	}

	_create_semaphore_file_if_need( output );

	if( output->config->is_sampled )
		_create_new_file(output);
}

void file_output_release( file_output_t *output ){
	EXPECT( output != NULL, );

	if( output->file ){
		fflush( output->file );

		if( output->config->is_sampled )
			fclose( output->file );
	}

	_create_semaphore_file_if_need( output );
	xfree( output );
}

int file_output_write( file_output_t *output, const char *format, ... ){
	int ret = 0;
	if( output && output->file ){
		va_list args;

		va_start( args, format );
		ret = vfprintf( output->file, format, args);
		vprintf( format, args );
		va_end( args );
	}
	return ret;
}
