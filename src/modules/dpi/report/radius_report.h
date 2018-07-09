/*
 * radius_report.h
 *
 *  Created on: May 7, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_REPORT_RADIUS_REPORT_H_
#define SRC_MODULES_DPI_REPORT_RADIUS_REPORT_H_

#include "../dpi.h"

typedef struct radius_report_context_struct radius_report_context_t;

radius_report_context_t *radius_report_register( mmt_handler_t *dpi_handler, const radius_report_conf_t *config, output_t *output );

void radius_report_unregister( mmt_handler_t *dpi_handler, radius_report_context_t *  );

#endif /* SRC_MODULES_DPI_REPORT_RADIUS_REPORT_H_ */
