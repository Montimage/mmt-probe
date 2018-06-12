/*
 * html_reconstruct.h
 *
 *  Created on: Apr 17, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_RECONSTRUCT_HTTP_HTTP_RECONSTRUCT_H_
#define SRC_MODULES_DPI_RECONSTRUCT_HTTP_HTTP_RECONSTRUCT_H_

#include <mmt_core.h>
#include "../../../../configure.h"

typedef struct http_reconstruct_struct http_reconstruct_t;

http_reconstruct_t *http_reconstruct_init( const reconstruct_data_conf_t *config, mmt_handler_t *dpi_handler );

typedef struct http_session_struct http_session_t;

void http_reconstruct_flush_session_to_file_and_free(  http_session_t * );

void http_reconstruct_append_data( const ipacket_t *ipacket );

#endif /* SRC_MODULES_DPI_RECONSTRUCT_HTTP_HTTP_RECONSTRUCT_H_ */
