/*
 * event_based_report.h
 *
 *  Created on: Apr 18, 2018
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_
#define SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_

typedef struct list_event_based_report_context_struct list_event_based_report_context_t;

/**
 * Register a list of event reports
 * @param dpi_handler
 * @param config
 * @param events_size
 * @param output
 * @return
 */
list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output );

/**
 * Unregister a list of event reports, thus release resources using by the event reports
 * @param dpi_handler
 * @param context
 */
void event_based_report_unregister( mmt_handler_t *dpi_handler, list_event_based_report_context_t *context  );


/**
 * This function needs to be called on each packet once it is classified
 * @param context
 * @param packet
 */
void event_based_report_callback_on_receiving_packet( const ipacket_t *packet, list_event_based_report_context_t *context);
#endif /* SRC_MODULES_DPI_REPORT_EVENT_BASED_REPORT_H_ */
