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
		uint32_t *proto_ids;
		uint32_t *att_ids;

		const event_report_conf_t *config;
		output_t *output;
}event_based_report_context_t;


struct list_event_based_report_context_struct{
	size_t event_reports_size;
	mmt_handler_t *dpi_handler;
	event_based_report_context_t* event_reports;
};


static inline void _add_quote_if_need( char *msg, int *offset, const attribute_t *att ){
	switch( att->data_type ){
	case MMT_BINARY_VAR_DATA:
	case MMT_DATA_CHAR:
	case MMT_DATA_DATE:
	case MMT_DATA_IP6_ADDR:
	case MMT_DATA_IP_ADDR:
	case MMT_DATA_IP_NET:
	case MMT_DATA_MAC_ADDR:
	case MMT_DATA_PATH:
	case MMT_HEADER_LINE:
	case MMT_STRING_DATA:
	case MMT_STRING_LONG_DATA:
	case MMT_GENERIC_HEADER_LINE:
		msg[ *offset ] = '"';
		*offset = *offset + 1;
		return;
	}
}

static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	event_based_report_context_t *context = (event_based_report_context_t *)arg;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;
	//event
	_add_quote_if_need( message, &offset, attribute );
	offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE, attribute );
	_add_quote_if_need( message, &offset, attribute );

	//attributes
	attribute_t * attr_extract;
	int i;
	for( i=0; i<context->config->attributes_size; i++ ){
		attr_extract = get_extracted_attribute( packet,
				context->proto_ids[i],
				context->att_ids[i] );

		//separator
		message[offset] = ',';
		offset ++;

		if( attr_extract == NULL ){
			//offset += snprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, "null" );
			offset += append_string( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, "null" );
		}else{
			_add_quote_if_need( message, &offset, attribute );
			offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
			_add_quote_if_need( message, &offset, attribute );
		}
	}

	message[offset] = '\0';

	output_write_report( context->output, context->config->output_channels,
			EVENT_REPORT_TYPE,
			&packet->p_hdr->ts, message );
}


list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output ){
	int i, j;

	//no event?
	list_event_based_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( list_event_based_report_context_t  ) );
	ret->event_reports_size = events_size;
	ret->event_reports = mmt_alloc_and_init_zero(  events_size * sizeof( event_based_report_context_t  ) );
	ret->dpi_handler = dpi_handler;

	for( i=0; i<events_size; i++ ){
		ret->event_reports[i].output = output;
		ret->event_reports[i].config = &config[i];

		ret->event_reports[i].att_ids = mmt_alloc( sizeof( uint32_t ) * config[i].attributes_size );
		ret->event_reports[i].proto_ids = mmt_alloc( sizeof( uint32_t ) * config[i].attributes_size );

		for( j=0; j<config[i].attributes_size; j++ )
			dpi_get_proto_id_and_att_id( & config[i].attributes[j], &ret->event_reports[i].proto_ids[j], &ret->event_reports[i].att_ids[j] );


		if( config[i].is_enable ){
			if( dpi_register_attribute( config[i].event, 1, dpi_handler, _event_report_handle, &ret->event_reports[i]) == 0 ){
				log_write( LOG_ERR, "Cannot register an event-based report [%s] for event [%s.%s]",
						config[i].title,
						config[i].attributes->proto_name,
						config[i].attributes->attribute_name );
				continue;
			}

			//register attribute to extract data
			dpi_register_attribute( config[i].attributes, config[i].attributes_size, dpi_handler, NULL, NULL );
		}
	}
	return ret;
}

void event_based_report_unregister( list_event_based_report_context_t *context  ){
	int i;
	const event_report_conf_t *config;
	if( context == NULL )
		return;

	for( i=0; i<context->event_reports_size; i++ ){
		mmt_probe_free( context->event_reports[i].att_ids );
		mmt_probe_free( context->event_reports[i].proto_ids );

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
