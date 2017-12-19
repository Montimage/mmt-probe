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

struct _user_data{
	uint16_t report_id;
	const worker_context_t *context;
};

static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	struct _user_data *user = (struct _user_data *)arg;
	const worker_context_t *worker_context = user->context;
	int id = user->report_id;
	const event_report_conf_t *conf = &worker_context->probe_context->config->reports.events[ id ];

	output_write( worker_context->output, &conf->output_channels, "hihi" );
}

static inline void _register_unregister( struct _user_data *args ){

	const worker_context_t *worker_context = args->context;
	const event_report_conf_t *conf = &worker_context->probe_context->config->reports.events[ args->report_id ];
	mmt_handler_t *mmt_dpi  = worker_context->dpi_handler;
	bool need_to_register = conf->is_enable;

	int i;

	uint32_t proto_id, att_id;
	if( ! dpi_get_proto_id_and_att_id( conf->event, &proto_id, &att_id ) ){
		log_write( LOG_ERR, "Does not support protocol %s and its attribute %s", conf->event->proto_name, conf->event->attribute_name );
		return;
	}

	//register event to handler
	if( is_registered_attribute_handler( mmt_dpi, proto_id, att_id, _event_report_handle) )
		unregister_attribute_handler( mmt_dpi, proto_id, att_id, _event_report_handle);

	if( need_to_register )
		if( !register_attribute_handler( mmt_dpi, proto_id, att_id, _event_report_handle, NULL, args ) ){
			log_write( LOG_ERR, "Cannot register for event-based report: %s.%s", conf->event->proto_name, conf->event->attribute_name );
			return;
		}

	//register attribute to extract data
	for( i=0; i<conf->attributes_size; i++ ){
		if( ! dpi_get_proto_id_and_att_id( &conf->attributes[i], &proto_id, &att_id ) ){
			log_write( LOG_ERR, "Does not support protocol %s and its attribute %s",
					conf->attributes[i].proto_name,
					conf->attributes[i].attribute_name);
			continue;
		}
		if( is_registered_attribute( mmt_dpi, proto_id, att_id) )
			unregister_extraction_attribute( mmt_dpi, proto_id, att_id);

		if( ! register_extraction_attribute( mmt_dpi, proto_id, att_id) )
			log_write( LOG_WARNING, "Cannot register attribute for event-based report: %s.%s",
					conf->attributes[i].proto_name,
					conf->attributes[i].attribute_name
					);
	}
}

void event_based_report_register( const worker_context_t *worker_context ){
	int i;
	const probe_conf_t *config = worker_context->probe_context->config;
	if( config->reports.events_size == 0 )
		return;

	struct _user_data **report_handlers = alloc( config->reports.events_size * sizeof( void *) );

	for( i=0; i<config->reports.events_size; i++ ){
		report_handlers[i] = alloc( sizeof( struct _user_data ));
		report_handlers[i]->report_id = i;
		report_handlers[i]->context   = worker_context;

		_register_unregister( report_handlers[i] );
	}
}
