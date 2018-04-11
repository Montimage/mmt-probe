/*
 * event_based_report.c
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */

#include "dpi_tool.h"
#include "dpi.h"
#include "../output/output.h"

typedef struct event_based_report_context_struct{
	const event_report_conf_t *config;
	output_t *output;

}event_based_report_context_t;

static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	event_based_report_context_t *context = (event_based_report_context_t *)arg;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];

	int offset = mmt_attr_sprintf( message, MAX_LENGTH_REPORT_MESSAGE, attribute );

	attribute_t * attr_extract;
	int i;
	for( i=0; i<context->config->attributes_size; i++ ){
		attr_extract = get_extracted_attribute_by_name( packet,
				context->config->attributes[i].proto_name,
				context->config->attributes[i].attribute_name );

		if( attr_extract == NULL )
			continue;

		//separator
		message[offset] = ',';
		offset ++;

		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
	}

	message[offset] = '\0';

	output_write_report( context->output, context->config->output_channels,
			EVENT_REPORT_TYPE,
			&packet->p_hdr->ts, message );
}


void event_based_report_register( dpi_context_t *dpi_context ){
	int i;
	const probe_conf_t *config = dpi_context->probe_config;
	mmt_handler_t *dpi_handler = dpi_context->dpi_handler;

	if( dpi_context->event_based_context != NULL ){
		//TODO: unregister?
	}


	//no event?
	event_based_report_context_t *ret = mmt_alloc( config->reports.events_size * sizeof( event_based_report_context_t  ) );

	for( i=0; i<config->reports.events_size; i++ ){
		ret[i].config = &(config->reports.events[i]);
		ret[i].output = dpi_context->output;

		if( config->reports.events[i].is_enable ){
			if( dpi_register_attribute( ret[i].config->event, 1, dpi_handler, _event_report_handle, &ret[i]) == 0 ){
				log_write( LOG_ERR, "Cannot register an event-based report" );
				return;
			}

			//register attribute to extract data
			dpi_register_attribute( ret[i].config->attributes, ret[i].config->attributes_size, dpi_handler, NULL, NULL );
		}
	}
	dpi_context->event_based_context = ret;
}

void event_based_report_unregister( dpi_context_t *dpi_context  ){
	int i;
	const probe_conf_t *config = dpi_context->probe_config;
	mmt_handler_t *dpi_handler = dpi_context->dpi_handler;
	const event_report_conf_t *ev;

	for( i=0; i<config->reports.events_size; i++ ){
		ev = & config->reports.events[i];
		if(! ev->is_enable )
			continue;

		//unregister event
		dpi_unregister_attribute( ev->event, 1, dpi_handler, _event_report_handle );

		//unregister attributes
		dpi_unregister_attribute( ev->attributes, ev->attributes_size, dpi_handler, NULL );
	}

	mmt_probe_free( dpi_context->event_based_context );
}
