/*
 * flow_stat.c
 *
 *  Created on: Dec 20, 2017
 *      Author: nhnghia
 */

#include <mmt_core.h>
#include "dpi.h"

#include "event_based_report.h"

dpi_context_t* dpi_alloc_init( worker_context_t *worker ){
	mmt_handler_t *mmt_dpi = worker->dpi_handler;
	const probe_conf_t *config= worker->probe_context->config;

	dpi_context_t *ret;
	//first time
	if( worker->dpi_context == NULL )
		ret = alloc( sizeof( dpi_context_t ) );
	else
		ret = worker->dpi_context;

	ret->worker_context = worker;

	ret->event_based_reports = event_based_report_register( ret );


	return ret;
}


void dpi_release( dpi_context_t *dpi ){
	event_based_report_unregister( dpi->event_based_reports );
	xfree( dpi );
}
