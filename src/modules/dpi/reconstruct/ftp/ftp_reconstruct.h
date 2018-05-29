/*
 * ftp_reconstruct.h
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_
#define SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_

#include <mmt_core.h>
#include "../../../../configure.h"

typedef struct ftp_reconstruct_struct ftp_reconstruct_context_t;

ftp_reconstruct_context_t *ftp_reconstruct_init( const reconstruct_data_conf_t *conf, mmt_handler_t *dpi_handler );
void ftp_reconstruct_release( ftp_reconstruct_context_t *context );

#endif /* SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_ */
