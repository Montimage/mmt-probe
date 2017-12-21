/*
 * event_based_report.c
 *
 *  Created on: Dec 19, 2017
 *      Author: nhnghia
 */

#include <mmt_core.h>
#include "dpi_tool.h"
#include "event_based_report.h"
#include "../../lib/alloc.h"
#include "../output/output.h"

struct event_based_report_context_struct{
	uint16_t report_id;
	const worker_context_t *worker_context;
};

static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	event_based_report_context_t *user = (event_based_report_context_t *)arg;
	const worker_context_t *worker_context = user->worker_context;
	int id = user->report_id;
	const event_report_conf_t *conf = &worker_context->probe_context->config->reports.events[ id ];

	char message[ MAX_LENGTH_REPORT_MESSAGE ];

	int offset = mmt_attr_sprintf( message, MAX_LENGTH_REPORT_MESSAGE, attribute );

	attribute_t * attr_extract;
	int i;
	for( i=0; i<conf->attributes_size; i++ ){
		attr_extract = get_extracted_attribute_by_name( packet, conf->attributes[i].proto_name, conf->attributes[i].attribute_name );
		if( attr_extract == NULL )
			continue;

		//separator
		message[offset] = ',';
		offset ++;

		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
	}

	message[offset] = '\0';

	output_write_report( worker_context->output, &conf->output_channels,
			EVENT_REPORT_TYPE, &packet->p_hdr->ts, "%s", message );
}

static inline void _register( event_based_report_context_t *args ){

	const worker_context_t *worker_context = args->worker_context;
	const event_report_conf_t *conf = &worker_context->probe_context->config->reports.events[ args->report_id ];
	mmt_handler_t *dpi_handler      = worker_context->dpi_handler;

	if( dpi_register_attribute( conf->event, 1, dpi_handler, _event_report_handle, args) == 0 ){
		log_write( LOG_ERR, "Cannot register an event-based report" );
		return;
	}

	//register attribute to extract data
	dpi_register_attribute( conf->attributes, conf->attributes_size, dpi_handler, NULL, NULL );
}

/**
 * Unregister all attributes/handlers being done by event-based reports
 * @param context
 */
static void inline _unregister_all(event_based_report_context_t *context  ){
	const probe_conf_t *config = context->worker_context->probe_context->config;
	mmt_handler_t *dpi_handler = context->worker_context->dpi_handler;

	int i;
	const event_report_conf_t *ev;
	for( i=0; i<config->reports.events_size; i++ ){
		ev = & config->reports.events[i];
		//unregister event
		dpi_unregister_attribute( ev->event, 1, dpi_handler, _event_report_handle );

		//unregister attributes
		dpi_unregister_attribute( ev->attributes, ev->attributes_size, dpi_handler, NULL );
	}
}

event_based_report_context_t* event_based_report_register( const dpi_context_t *dpi_context ){
	int i;
	const probe_conf_t *config = dpi_context->worker_context->probe_context->config;
	if( config->reports.events_size == 0 )
		return NULL;

	//Already registered
	if( dpi_context->event_based_reports != NULL ){

	}

	event_based_report_context_t *ret = alloc( config->reports.events_size * sizeof( event_based_report_context_t  ) );

	for( i=0; i<config->reports.events_size; i++ ){
		if( ! config->reports.events[i].is_enable )
			continue;

		ret[i].report_id      = i;
		ret[i].worker_context = dpi_context->worker_context;

		_register( &ret[i] );
	}
	return ret;
}

void event_based_report_unregister( event_based_report_context_t *context  ){
	_unregister_all(context);
	xfree( context );
}
