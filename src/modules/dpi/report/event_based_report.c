/*
 * event_based_report.c
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */
#include <mmt_core.h>
#include "../dpi_tool.h"
#include "../../output/output.h"
#include "event_based_report.h"

typedef struct event_based_report_context_struct {
		const event_report_conf_t *config;
		output_t *output;
}event_based_report_context_t;


struct list_event_based_report_context_struct{
	size_t event_reports_size;
	mmt_handler_t *dpi_handler;
	event_based_report_context_t* event_reports;
};

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

		//separator
		message[offset] = ',';
		offset ++;

		if( attr_extract == NULL ){
			offset += snprintf( message, sizeof( message ) - offset, "null" );
		}else{
			offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
		}
	}

	message[offset] = '\0';

	output_write_report( context->output, context->config->output_channels,
			EVENT_REPORT_TYPE,
			&packet->p_hdr->ts, message );
}


list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output ){
	int i;

	//no event?
	list_event_based_report_context_t *ret = mmt_alloc( sizeof( list_event_based_report_context_t  ) );
	ret->event_reports_size = events_size;
	ret->event_reports = mmt_alloc(  events_size * sizeof( event_based_report_context_t  ) );
	ret->dpi_handler = dpi_handler;

	for( i=0; i<events_size; i++ ){
		ret->event_reports[i].config = &(config[i]);
		ret->event_reports[i].output = output;

		if( config[i].is_enable ){
			if( dpi_register_attribute( ret->event_reports[i].config->event, 1, dpi_handler, _event_report_handle, &ret->event_reports[i]) == 0 ){
				log_write( LOG_ERR, "Cannot register an event-based report" );
				return NULL;
			}

			//register attribute to extract data
			dpi_register_attribute( ret->event_reports[i].config->attributes, ret->event_reports[i].config->attributes_size, dpi_handler, NULL, NULL );
		}
	}
	return ret;
}

void event_based_report_unregister( list_event_based_report_context_t *context  ){
	int i;
	const event_report_conf_t *config;

	for( i=0; i<context->event_reports_size; i++ ){
		config = context->event_reports[i].config;
		//jump over the disable ones
		if(! config->is_enable )
			continue;

		//unregister event
		dpi_unregister_attribute( config->event, 1, context->dpi_handler, _event_report_handle );

		//unregister attributes
		dpi_unregister_attribute( config->attributes, config->attributes_size, context->dpi_handler, NULL );
	}

	mmt_probe_free( context->event_reports );
	mmt_probe_free( context );
}
