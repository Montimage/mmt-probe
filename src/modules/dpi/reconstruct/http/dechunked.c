/*
 * dechunked.c
 *
 *  Created on: Jun 14, 2018
 *          by: Huu Nghia Nguyen
 */
#include <stdbool.h>
#include "dechunked.h"
#include "../../../../lib/log.h"

static inline bool _is_new_line( const char* data ){
	return (data[0] == '\r' && data[1] == '\n');
}

static inline uint32_t _get_chunk_size( const char *data, uint32_t *chunk_size ){
	char *c;
	long val = strtol(data, &c, 16 ); //in hexa format
	if( chunk_size )
		*chunk_size = val;
	return (c - data );
}
uint32_t chunk_decode( char *buffer, const char *data, uint32_t data_len ){
	int index = 0, i;
	uint32_t chunk_size;
	uint32_t ret = 0, j = 0;

	while( j < data_len ){
		//chunk size
		j += _get_chunk_size( data+j, &chunk_size );
		//we are in the last chunk
		if( chunk_size == 0 )
			break;
		//no place for chunk size
		if( j>data_len )
			goto _bad_format;

		//no CRLF?
		if( ! _is_new_line( data+j ))
			goto _bad_format;

		j += 2; //jump over CRLF
		if( j>data_len )
			goto _bad_format;

		//chunk size is too big
		if( chunk_size > data_len - j ) //2characters of CRLF at the end of chunk
			goto _bad_format;

		//copy real data to buffer
		for( i=0; i<chunk_size; i++ ){
			buffer[ index ++ ] = data[ j++ ];
		}

		//no CRLF?
		if( ! _is_new_line( data+j ))
			goto _bad_format;
		j += 2; //jump over CRLF
	}

	return ret;

	//Chunk is not well-formatted
	_bad_format:
	return 0;
}
