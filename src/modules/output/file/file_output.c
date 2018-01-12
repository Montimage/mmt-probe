/*
 * file_output.c
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */

#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

#include "../../../lib/alloc.h"
#include "file_output.h"

#include "../../../lib/limit.h"

struct file_output_struct{
	uint16_t id;
	struct timeval created_time_of_file;

	FILE *file;
	const file_output_conf_t *config;
};

static int _load_filter( const struct dirent *entry ){
	const char *data_out = ".csv";
	//must end by .csv
	char *ext = strstr( entry->d_name, data_out );
	if( ext == NULL ) return 0;
	return (strlen( ext ) == strlen( data_out ));
}

/**
 * Remove old sampled files in #folder
 * Sample file name in format: xxxxxxxxxx_abc.csv and its semaphore in format: xxxxxxxxxx_abc.csv.sem
 *  in which xxxxxxxxxx is a number represeting timestamp when the file was created
 */
static int _remove_old_sampled_files(const char *folder, size_t retains){
	struct dirent **entries, *entry;
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	int i, n, ret, to_remove;

	n = scandir( folder, &entries, _load_filter, alphasort );
	if( n < 0 ) {
		log_write( LOG_ERR, "Cannot scan output_dir: %s", strerror( errno ) );
		return 0;
	}

	to_remove = n - retains;
	//printf("total file %d, retains: %zu, to remove %d\n", n, retains, to_remove );
	if( to_remove < 0 ) to_remove = 0;

	for( i = 0 ; i < to_remove ; ++i ) {
		entry = entries[i];
		snprintf( file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%s", folder, entry->d_name );

		ret = unlink( file_name );
		if( ret ){
			log_write( LOG_ERR, "Cannot delete old sampled files: %s", strerror( errno ));
			continue;
		}

		snprintf( file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%s.sem", folder, entry->d_name );

		ret = unlink( file_name );
		if( ret ){
			log_write( LOG_ERR, "Cannot delete semaphore of old sampled file '%s': %s", file_name, strerror( errno ));
			continue;
		}
	}

	for( i = 0; i < n; i++ )
		free( entries[ i ] );
	free( entries );

	return to_remove;
}

static inline void _create_new_file( file_output_t *output ){
	char filename[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

	//create output file
	gettimeofday( &output->created_time_of_file, NULL );

	snprintf( filename, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%lu_%06zu_%02d_%s",
			output->config->directory,
			output->created_time_of_file.tv_sec,
			output->created_time_of_file.tv_usec,
			output->id,
			output->config->filename );
	output->file = fopen( filename,"w");

	if( output->file == NULL )
		log_write( LOG_ERR, "Cannot create data file %s: %s", filename, strerror( errno ) );

	//log_debug("Create file output %s", filename );

	//the first output
	if( output->id == 0 && output->config->retained_files_count > 0 )
		_remove_old_sampled_files( output->config->directory, output->config->retained_files_count  );

}

file_output_t* file_output_alloc_init( const file_output_conf_t *config, uint16_t id ){
	if( config->is_enable == false )
		return NULL;

	file_output_t *ret = alloc( sizeof( file_output_t) );
	ret->file          = NULL;
	ret->config        = config;
	ret->id            = id;
	//init file, created_time_of_file
	_create_new_file( ret );
	return ret;
}


static inline void _create_semaphore_file_if_need( file_output_t *output ){
	if( output && output->file && output->config->is_sampled ){
		char filename[ MAX_LENGTH_FULL_PATH_FILE_NAME ];

		//create semaphore
		snprintf( filename, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s/%lu_%06zu_%02d_%s.sem",
				output->config->directory,
				output->created_time_of_file.tv_sec,
				output->created_time_of_file.tv_usec,
				output->id,
				output->config->filename );
		FILE *file = fopen( filename,"w");
		if( file == NULL )
			log_write( LOG_ERR, "Cannot create semaphore file %s: %s", filename, strerror( errno ) );
		else
			fclose( file );
	}
}


void file_output_flush( file_output_t * output){
	EXPECT( output != NULL && output->file != NULL,  );

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

	if( output->file )
		fclose( output->file );

	_create_semaphore_file_if_need( output );
	xfree( output );
}

int file_output_write( file_output_t *output, const char *message ){
	EXPECT( output != NULL && output->file != NULL && message != NULL, 0 );

	int ret = 0;
	if( output && output->file ){
		ret = fprintf( output->file, "%s\n", message );
		//printf( "%s\n", message );
	}
	return ret;
}

int file_output_write_( file_output_t *output, const char *format, ... ){
	EXPECT( output != NULL && output->file != NULL && format != NULL, 0 );
	int ret = 0;
	if( output && output->file ){
		va_list args;

		va_start( args, format );
		ret = vfprintf( output->file, format, args);
		//vprintf( format, args );
		va_end( args );
	}
	return ret;
}