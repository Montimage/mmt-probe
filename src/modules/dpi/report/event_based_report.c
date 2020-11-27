/*
 * event_based_report.c
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */
#include <mmt_core.h>
#include "../dpi_tool.h"
#include "../../output/output.h"
#include "../../../lib/malloc_ext.h"
#include "event_based_report.h"

typedef struct event_based_report_context_struct {
		uint32_t *proto_ids;
		uint32_t *att_ids;

		const event_report_conf_t *config;
		output_t *output;
}event_based_report_context_t;


struct list_event_based_report_context_struct{
	size_t event_reports_size;
	event_based_report_context_t* event_reports;
};

/**
 * Surround the quotes for the string data
 * @param msg
 * @param offset
 * @param att
 */
static inline bool _is_string( int data_type ){
	switch( data_type ){
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
		return true;
	}
	return false;
}

//specical attribute format
#define PROTO_IEEE802154 800
#define IEEE802154_DST_ADDRESS_EXTENDED 10
#define IEEE802154_SRC_ADDRESS_EXTENDED 13
static int _process_ieee802154_src_dst( char *msg, int length, uint32_t proto_id, uint32_t att_id, const attribute_t *data ){
	if( proto_id != PROTO_IEEE802154 )
		return 0;
	if( att_id != IEEE802154_SRC_ADDRESS_EXTENDED && att_id != IEEE802154_DST_ADDRESS_EXTENDED)
		return 0;
	//no data => use empty string
	if( data == NULL || data->data == NULL){
		msg[0] = '"';
		msg[1] = '"';
		return 2; //2 characters have been added to msg
	}

	uint8_t *add = (uint8_t *) data->data;

	int len = snprintf( msg , length, "\"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\"",
			add[7], add[6], add[5], add[4], add[3], add[2], add[1], add[0] );

	return len;
}

/**
 * This callback is called by DPI when it sees one of the attributes in a event report.
 * @param packet
 * @param attribute
 * @param arg
 */
static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	event_based_report_context_t *context = (event_based_report_context_t *)arg;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;



	//event id
	offset += append_string( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, context->config->title );
	//separator
	message[offset] = ',';
	offset ++;

	//event data
	if( _is_string( attribute->data_type ) ){
		//surround by quotes
		message[ offset ++ ] = '"';
		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE, attribute );
		message[ offset ++ ] = '"';
	}else
		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE, attribute );

	//attributes
	attribute_t * attr_extract;
	int i;
	for( i=0; i<context->config->attributes_size; i++ ){
		attr_extract = get_extracted_attribute( packet,
				context->proto_ids[i],
				context->att_ids[i] );

		//separator
		message[offset ++] = ',';

		//special processing for IEEE_802154
		int ret = _process_ieee802154_src_dst( message+offset, MAX_LENGTH_REPORT_MESSAGE - offset,
				context->proto_ids[i], context->att_ids[i], attr_extract);
		offset += ret;

		//one of attributes of IEEE_802154 has been processed?
		if( ret != 0 )
			continue;

		if( attr_extract != NULL ){
			if( _is_string( attr_extract->data_type ) ){
				//surround by quotes
				message[ offset ++ ] = '"';
				if( attr_extract != NULL )
					offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
				message[ offset ++ ] = '"';
			}

			else
				offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract );
		}else{
			//no value, use default value:
			// "" for string
			// 0  for number
			if( _is_string( get_attribute_data_type( context->proto_ids[i],
				context->att_ids[i] ) )){
				message[ offset ++ ] = '"';
				message[ offset ++ ] = '"';
			}else
				message[ offset ++ ] = '0';
		}
	}

	message[offset] = '\0';

	output_write_report( context->output, context->config->output_channels,
			EVENT_REPORT_TYPE,
			&packet->p_hdr->ts, message );
}

//Public API
list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output ){
	int i, j;

	//no event?
	list_event_based_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( list_event_based_report_context_t  ) );
	ret->event_reports_size = events_size;
	ret->event_reports = mmt_alloc_and_init_zero(  events_size * sizeof( event_based_report_context_t  ) );

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

//Public API
void event_based_report_unregister( mmt_handler_t *dpi_handler, list_event_based_report_context_t *context  ){
	int i;
	const event_report_conf_t *config;
	if( context == NULL )
		return;

	for( i=0; i<context->event_reports_size; i++ ){
		mmt_probe_free( context->event_reports[i].att_ids );
		mmt_probe_free( context->event_reports[i].proto_ids );

		config = context->event_reports[i].config;
		//jump over the disable ones
		//This can create a leak when this event report is disable in runtime
		//(this is, it was enable at starting time but it has been disable after some time of running)
		//So, when it has been disable, one must unregister the attributes using by this event report
		if(! config->is_enable )
			continue;

		//unregister event
		dpi_unregister_attribute( config->event, 1, dpi_handler, _event_report_handle );

		//unregister attributes
		dpi_unregister_attribute( config->attributes, config->attributes_size, dpi_handler, NULL );
	}

	mmt_probe_free( context->event_reports );
	mmt_probe_free( context );
}
