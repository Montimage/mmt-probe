/*
 * event_based_report.h
 *
 *  Created on: Dec 19, 2017
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_EVENT_BASED_REPORT_H_
#define SRC_MODULES_DPI_EVENT_BASED_REPORT_H_

#include "dpi.h"

event_based_report_context_t* event_based_report_register( const dpi_context_t *dpi_context );
void event_based_report_unregister( event_based_report_context_t *context  );

#endif /* SRC_MODULES_DPI_EVENT_BASED_REPORT_H_ */
