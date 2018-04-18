/*
 * event_based_report.h
 *
 *  Created on: Apr 18, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_
#define SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_

typedef struct list_event_based_report_context_struct list_event_based_report_context_t;

list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output );

void event_based_report_unregister( list_event_based_report_context_t *context  );

#endif /* SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_ */
