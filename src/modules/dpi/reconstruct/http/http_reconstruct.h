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

#endif /* SRC_MODULES_DPI_RECONSTRUCT_HTTP_HTTP_RECONSTRUCT_H_ */
