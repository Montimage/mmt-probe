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

#include "file_output.h"

#include "../../../lib/limit.h"
#include "../../../lib/malloc.h"
#include "../../../lib/string_builder.h"

struct file_output_struct{
	uint16_t id;
	uint32_t nb_messages;
	char *file_name;

	FILE *file;
	const file_output_conf_t *config;
};

#define SEMAPHORE_EXT ".sem"
//number of characters in a literal string (-1 to exclude '\0' character at the end)
#define STR_LITERAL_LEN( x ) (sizeof( x ) - 1)

static int _load_filter( const struct dirent *entry ){
	char *ext = strstr( entry->d_name, SEMAPHORE_EXT );
	if( ext == NULL ) return 0;
	return (strlen( ext ) == (sizeof( SEMAPHORE_EXT ) - 1) );
}

/**
 * Remove old sampled files in #folder
 * Sample file name in format: xxxxxxxxxx_abc.csv and its semaphore in format: xxxxxxxxxx_abc.csv.sem
 *  in which xxxxxxxxxx is a number representing timestamp when the file was created
 */
static inline int _remove_old_sampled_files(const char *folder, size_t retains){
	struct dirent **entries, *entry;
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	int i, n, ret, to_remove, len, offset;

	n = scandir( folder, &entries, _load_filter, alphasort );
	if( n < 0 ) {
		log_write( LOG_ERR, "Cannot scan output_dir (%s): %s", folder, strerror( errno ) );
		return 0;
	}

	to_remove = n - retains;
	//printf("total file %d, retains: %zu, to remove %d\n", n, retains, to_remove );
	if( to_remove < 0 ) to_remove = 0;

	//preserve folder in file_name
	offset = strlen( folder );
	memcpy( file_name, folder, offset );

	//ensure folder is end by /
	if( file_name[ offset - 1 ] != '/' )
		file_name[ offset ++ ] = '/';

	//list of semaphore file
	for( i = 0 ; i < to_remove ; ++i ) {
		entry = entries[i];

		len = strlen( entry->d_name );

		//not enough room to contain file name
		if( len + offset >= sizeof( file_name ) ){
			log_write( LOG_WARNING, "Filename is too big: %s%s", file_name, entry->d_name );
			continue;
		}

		//semaphore file
		memcpy(file_name + offset, entry->d_name, len + 1 ); //+1 to copy also '\0' character

		//delete semaphore
		ret = unlink( file_name );
		if( ret )
			log_write( LOG_ERR, "Cannot delete semaphore of old sampled file '%s': %s", file_name, strerror( errno ));

		//get csv file name by excluding .sem
		file_name[ offset + len - STR_LITERAL_LEN( SEMAPHORE_EXT ) ] = '\0'; //cut .sem

		//csv file is not here, why???
		//if( access( file_name, F_OK ) == -1 )
		//    continue;

		//delete csv files
		ret = unlink( file_name );
		if( ret )
			log_write( LOG_ERR, "Cannot delete old sampled files %s: %s", file_name, strerror( errno ));
	}

	for( i = 0; i < n; i++ )
		free( entries[ i ] );
	free( entries );

	return to_remove;
}

static inline void _create_new_file( file_output_t *output ){
	int valid = 0;

	output->nb_messages = 0;
	//create output file
	struct timeval created_time_of_file;
	gettimeofday( &created_time_of_file, NULL );

	STRING_BUILDER( valid, output->file_name, MAX_LENGTH_FULL_PATH_FILE_NAME,
			//"%s/%lu-%06zu_%02d_%s",
			__ARR( output->config->directory ),
			__TIME( &created_time_of_file ),
			__CHAR( '_' ),
			__INT( output->id ),
			__CHAR( '_' ),
			__ARR( output->config->filename )
	);
	output->file = fopen( output->file_name,"w");

	if( output->file == NULL )
		log_write( LOG_ERR, "Cannot create data file %s: %s", output->file_name, strerror( errno ) );

	//use the first one to limit number of output files
	if( output->id == 1 && output->config->retained_files_count > 0 )
		_remove_old_sampled_files( output->config->directory, output->config->retained_files_count  );
}

file_output_t* file_output_alloc_init( const file_output_conf_t *config, uint16_t id ){
	if( config->is_enable == false )
		return NULL;

	file_output_t *ret = mmt_alloc( sizeof( file_output_t) );
	ret->file          = NULL;
	ret->config        = config;
	ret->id            = id;
	ret->nb_messages   = 0;
	//this is full filename path of .csv file
	ret->file_name     = mmt_alloc( MAX_LENGTH_FULL_PATH_FILE_NAME );
	//init file, created_time_of_file
	_create_new_file( ret );
	return ret;
}


static inline void _create_semaphore_file( const file_output_t *output ){
	char filename[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	int valid = 0;

	bool has_data = (output->nb_messages > 0);

	//when the .csv file does not contain anything => delete it and no need to create its .sem file
	if( unlikely( ! has_data )){
		unlink( output->file_name );
		return;
	}

	//create semaphore
	STRING_BUILDER( valid, filename, MAX_LENGTH_FULL_PATH_FILE_NAME,
				__ARR( output->file_name ),
				__ARR( SEMAPHORE_EXT )
	);

	FILE *file = fopen( filename,"w");
	if( file == NULL )
		log_write( LOG_ERR, "Cannot create semaphore file %s: %s", filename, strerror( errno ) );
	else
		fclose( file );
}


void file_output_flush( file_output_t * output){
	EXPECT( output != NULL && output->file != NULL,  );

//	DEBUG("flush file %d\n", output->id );
	fflush( output->file );

	if( output->config->is_sampled ){
		//close csv file
		fclose( output->file );
		output->file = NULL;

		_create_semaphore_file( output );
		_create_new_file(output);
	}
}

void file_output_release( file_output_t *output ){
	EXPECT( output != NULL, );

	if( output->file ){
		fclose( output->file );
		output->file = NULL;

		if( output->config->is_sampled )
			_create_semaphore_file( output );
	}

	mmt_probe_free( output->file_name );

	//use the first one to limit number of output files
	if( output->id == 0 && output->config->retained_files_count > 0 )
		_remove_old_sampled_files( output->config->directory, output->config->retained_files_count  );

	mmt_probe_free( output );
}

int file_output_write( file_output_t *output, const char *message ){
	EXPECT( output != NULL && output->file != NULL && message != NULL, 0 );

	output->nb_messages ++;
	int ret = fprintf( output->file, "%s\n", message );
	return ret;
}

