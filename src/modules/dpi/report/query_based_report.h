/*
 * query_based_report.h
 *
 *  Created on: Mar 31, 2022
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_REPORT_QUERY_BASED_REPORT_H_
#define SRC_MODULES_DPI_REPORT_QUERY_BASED_REPORT_H_

#include <stdbool.h>

typedef struct list_query_based_report_context_struct list_query_based_report_context_t;

list_query_based_report_context_t *query_based_report_register( mmt_handler_t *dpi_handler, const query_report_conf_t *config, size_t size, output_t *output);

void query_based_report_unregister( mmt_handler_t *dpi_handler, list_query_based_report_context_t *context  );

void query_based_report_callback_on_receiving_packet( const ipacket_t *packet, list_query_based_report_context_t *context);

void query_based_report_do_report( list_query_based_report_context_t *context );

void query_based_report_update_timer( list_query_based_report_context_t *context, const struct timeval *tv );

#endif /* SRC_MODULES_DPI_REPORT_QUERY_BASED_REPORT_H_ */
