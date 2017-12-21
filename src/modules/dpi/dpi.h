/*
 * flow_stat.h
 *
 *  Created on: Dec 20, 2017
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_FLOW_STAT_H_
#define SRC_MODULES_DPI_FLOW_STAT_H_

#include "../../lib/worker.h"

typedef struct event_based_report_context_struct event_based_report_context_t;

struct dpi_context_struct{
	const worker_context_t *worker_context;
	event_based_report_context_t *event_based_reports;
};


dpi_context_t* dpi_alloc_init( worker_context_t *worker );

void dpi_release( dpi_context_t *dpi );

#endif /* SRC_MODULES_DPI_FLOW_STAT_H_ */
