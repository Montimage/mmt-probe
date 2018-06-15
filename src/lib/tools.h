/*
 * tools.h
 *
 *  Created on: Dec 15, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_TOOLS_H_
#define SRC_LIB_TOOLS_H_
#include <sys/time.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <ctype.h>

#include "optimization.h"
#include "log.h"

#define MIN( a, b ) (a>b? b : a )
#define MAX( a, b ) (a<b? b : a )
#define SWAP(x, y, T) do { T tmp = x; x = y; y = tmp; } while (0)

#define MICRO_PER_SEC 1000000

/**
 * Convert a string to an integer.
 * If the result number is outside of [#low, #high] then it will be assigned to #def
 * @param string
 * @param low
 * @param high
 * @param def
 * @return
 */
static ALWAYS_INLINE int mmt_atoi( const char*string, int low, int high, int def ){
	int ret = atoi( string );
	if( ret > high || ret < low ){
		ret = def;
	}
	return ret;
}

/**
 * Get interval, in micro seconds, between two timeval moments
 * @param end
 * @param start
 */
static ALWAYS_INLINE long u_second_diff( const struct timeval *end, const struct timeval *start ){
	return ( end->tv_sec - start->tv_sec ) * MICRO_PER_SEC + ( end->tv_usec - start->tv_usec );
}

/**
 * Get number of micro seconds of a timeval
 * @param ts
 * @return
 */
static ALWAYS_INLINE size_t u_second( const struct timeval *ts ){
	return ts->tv_sec  * MICRO_PER_SEC + ts->tv_usec;
}

/**
 * Get milli seconds of a timeval
 * @param ts
 * @return
 */
static ALWAYS_INLINE size_t m_second( const struct timeval *ts ){
	return (ts->tv_sec  << 10) + (ts->tv_usec >> 10);
}


/**
 * Check whether a string has a prefix
 * @param string
 * @param prefix
 * @param prefix_len
 * @return
 */
static ALWAYS_INLINE bool is_started_by( const char *string, const char *prefix, size_t prefix_len ){
	int i;
	for( i=0; i<prefix_len; i++ )
		if( string[i] != prefix[i] )
			return false;
	return true;
}


#define IS_EQUAL_STRINGS( s1, s2 ) (strcmp(s1, s2) == 0)


static inline ssize_t append_data_to_file(const char *file_path, const void *content, size_t len) {
	int fd;
	fd = open( file_path, O_CREAT | O_WRONLY | O_APPEND | O_NOFOLLOW, S_IRUSR | S_IWUSR );
	if ( fd < 0 ) {
		log_write( LOG_ERR, "Error %d while writing data to \"%s\": %s", errno, file_path, strerror( errno ) );
		return -1;
	}

	ssize_t ret = write( fd, content, len );
	close ( fd );
	return ret;
}

static inline ssize_t write_data_to_file(const char *file_path, const void *content, size_t len) {
	int fd;
	fd = open( file_path, O_CREAT | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR );
	if ( fd < 0 ) {
		log_write( LOG_ERR, "Error %d while writing data to \"%s\": %s", errno, file_path, strerror( errno ) );
		return -1;
	}

	ssize_t ret = write( fd, content, len );
	close ( fd );
	return ret;
}

static inline size_t string_split(
		char       *buffer,     ///< In/Out : Modifiable String Buffer To Tokenise
		const char *separator,  ///< In     : Separator
		char       *argv[],     ///< Out    : Argument String Vector Array
		size_t     argv_length  ///< In     : Maximum Count For `*argv[]`
)
{ /* Tokenise string buffer into argc and argv format (req: string.h) */
	int i = 0;
	for( ; i < argv_length ; i++){ /* Fill argv via strtok_r() */
		if ( NULL == (argv[i] = strtok_r( NULL, separator, &buffer)) )
			break;
	}
	return i; // Argument Count
}

/**
 * Replace unreadable characters and slash by underscore character
 * @param file_name
 * @param size is size of file_name, set to zero to reach until NULL character
 * @return length of file_name
 */
static inline int string_format_file_name( char *file_name, size_t size ){
	int i;
	if( size == 0 )
		size = INT16_MAX;
	for( i=0; i<size && file_name[i] != '\0'; i++ )
		if( isalnum( file_name[i] )   )
			continue;
		else{
			switch( file_name[i] ){
			case '/':
				file_name[i] = '=';
				continue;
			case '=':
			case '?':
			case '&':
			case ':':
			case '|':
			case '"':
			case '>':
			case '<':
			case ' ':
				file_name[i] = '_';
				continue;
			default:
				continue;
			}
		}
	return i;
}
#endif /* SRC_LIB_TOOLS_H_ */
