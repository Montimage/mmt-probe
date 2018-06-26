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

http_reconstruct_t *http_reconstruct_init( const reconstruct_data_conf_t *config, mmt_handler_t *dpi_handler, output_t *output );
void http_reconstruct_close( mmt_handler_t *dpi_handler, http_reconstruct_t *context);
void http_reconstruct_release( http_reconstruct_t* );

typedef struct http_session_struct http_session_t;

typedef enum{
	HTTP_RECONSTRUCT_SUCCESS                = 0, //successfully reconstruct HTTP data
	HTTP_RECONSTRUCT_INCOMPLETE_CHUNK       = 1, //
	HTTP_RECONSTRUCT_FILE_CORRUPTED         = 2,
	HTTP_RECONSTRUCT_UNSUPPORT_ENCODING     = 3
} http_reconstruct_status_t;

/**
 * this function must be called at the end of each tcp/ip session
 */
void http_reconstruct_flush_session_to_file_and_free(  http_session_t * );

#endif /* SRC_MODULES_DPI_RECONSTRUCT_HTTP_HTTP_RECONSTRUCT_H_ */
