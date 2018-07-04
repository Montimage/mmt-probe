/*
 * ftp_reconstruct.h
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 *
 * Reconstruct data from FTP session.
 */

#ifndef SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_
#define SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_

#include <mmt_core.h>
#include "../../../../configure.h"

typedef struct ftp_reconstruct_struct ftp_reconstruct_context_t;

/**
 * Initialize FTP reconstruction
 * @param conf
 * @param dpi_handler
 * @return
 */
ftp_reconstruct_context_t *ftp_reconstruct_init( const reconstruct_data_conf_t *conf, mmt_handler_t *dpi_handler );

/**
 * Finish FTP reconstruction
 * This function must be called before ftp_reconstruct_release to unregister DPI attribute extraction.
 * @param dpi_handler
 * @param context
 */
void ftp_reconstruct_close( mmt_handler_t *dpi_handler, ftp_reconstruct_context_t *context);

/**
 * Free resource using by FTP construction
 * @param context
 */
void ftp_reconstruct_release( ftp_reconstruct_context_t *context );
#endif /* SRC_MODULES_DPI_RECONSTRUCT_FTP_FTP_RECONSTRUCT_H_ */
