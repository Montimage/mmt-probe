/*
 * dechunked.c
 *
 *  Created on: Jun 14, 2018
 *          by: Huu Nghia Nguyen
 */
#include <stdio.h>
#include <zlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include "../../../../lib/optimization.h"
#include "../../../../lib/log.h"
#include "decode.h"

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
	uint32_t j = 0;

	while( j < data_len ){
		//chunk size
		j += _get_chunk_size( data+j, &chunk_size );
		//we are in the last chunk
		if( chunk_size == 0 )
			break;

		//no place for chunk size
		if( j+2 > data_len )
			goto _bad_format;

		//no CRLF?
		if( ! _is_new_line( data+j ))
			goto _bad_format;

		j += 2; //jump over CRLF
		if( j>data_len )
			goto _bad_format;

		//chunk size is too big
		if( chunk_size > data_len - j )
			chunk_size = data_len - j;

		//copy real data to buffer
		for( i=0; i<chunk_size; i++ )
			buffer[ index ++ ] = data[ j++ ];

		//data does not contain a complete chunk
		//no CRLF?
		if( j+2 > data_len )
			goto _chunk_not_finish;

		if( ! _is_new_line( data+j ))
			goto _chunk_not_finish;
		j += 2; //jump over CRLF
	}

	_chunk_not_finish:
	return index;

	//Chunk is not well-formatted
	_bad_format:
	return 0;
}




/**
 * unzip data
 */
uint32_t zip_decode( const char *output_file_name, const char  *input_file_name ){

	/* CHUNK is the size of the memory chunk used by the zlib routines. */
	#define CHUNK 0x4000

	/* These are parameters to inflateInit2. See
	   http://zlib.net/manual.html for the exact meanings. */
	#define windowBits       15
	#define ENABLE_ZLIB_GZIP 32

	FILE * input_file = NULL, *output_file = NULL;
	z_stream strm = {0};
	unsigned char in[CHUNK];
	unsigned char out[CHUNK];

	//total output size
	uint32_t output_size = 0;

	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.next_in = in;
	strm.avail_in = 0;

	/*calls a zlib routine and checks the return value.
	   If the return value ("status") is not OK, it prints an error
	   message and exits the program. Zlib's error statuses are all less
	   than zero. */
	int status = inflateInit2 (&strm, windowBits | ENABLE_ZLIB_GZIP);
	if (status < 0) {
		log_write( LOG_ERR, "Cannot initialize zlib returned a bad status of %d.\n", status);
		goto _unzip_fail;
	}

	/* Open the files. */
	input_file = fopen (input_file_name, "rb");
	if( unlikely( input_file == NULL )){
		log_write( LOG_ERR, "Cannot open file %s to gunzip: %s", input_file_name, strerror( errno ) );
		goto _unzip_fail;
	}

	output_file = fopen (output_file_name, "wb");
	if( unlikely( output_file == NULL )){
		log_write( LOG_ERR, "Cannot open file %s to write: %s", output_file_name, strerror( errno ) );
		goto _unzip_fail;
	}

	while (1) {
		//read each chunk from input file
		int bytes_read = fread (in, sizeof (char), sizeof (in), input_file);
		if (ferror (input_file)){
			log_write( LOG_ERR, "Error while gunzip file %s: %s", input_file_name, strerror( errno) );
			goto _unzip_fail;
		}

		strm.avail_in = bytes_read;
		strm.next_in = in;

		do {
			unsigned have;
			strm.avail_out = CHUNK;
			strm.next_out = out;
			int zlib_status = inflate ( &strm, Z_NO_FLUSH );
			switch (zlib_status) {
			case Z_OK:
			case Z_STREAM_END:
			case Z_BUF_ERROR:
				break;

			default:
				DEBUG("gzip file is mal-formatted: %s", input_file_name );
				goto _unzip_fail;
			}

			//write output to file
			have = CHUNK - strm.avail_out;
			fwrite( out, sizeof (unsigned char), have, output_file );
			output_size += have;

		} while (strm.avail_out == 0);

		if( feof(input_file) )
			goto _unzip_end;
	}

	_unzip_fail:
	unlink( output_file_name ); //remove output file when error
	output_size = 0; //mark error

	_unzip_end:
	inflateEnd(& strm);
	if( input_file )
		fclose( input_file );
	if( output_file )
		fclose( output_file );

	return output_size;
}

