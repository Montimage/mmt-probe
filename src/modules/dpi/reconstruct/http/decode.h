/*
 * decode.h
 *
 *  Created on: Jun 14, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_RECONSTRUCT_HTTP_DECODE_H_
#define SRC_MODULES_DPI_RECONSTRUCT_HTTP_DECODE_H_

#include <stdint.h>
#include <stdbool.h>

/**
 * De-chunk data from chunks to buffer
 * @param buffer must have size bigger than or equal chunk_size
 * @param data
 * @param chunk_size
 * @return size of buffer if success
 *         0 if chunks are not well-formatted
 *
 */
uint32_t chunk_decode( char *buffer, const char *chunks, uint32_t chunk_size );


/**
 * Decode gzip format
 * @param output_file_name
 * @param input_file_name
 * @return 0 if data in input file is not well-formatted
 *    otherwise size of output file
 */
uint32_t zip_decode( const char *output_file_name, const char  *input_file_name );

#endif /* SRC_MODULES_DPI_RECONSTRUCT_HTTP_DECODE_H_ */
