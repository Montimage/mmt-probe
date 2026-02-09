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
	const event_report_conf_t *config;
	output_t *output;
	/**
	 * the latest values of the protocols and attributes to be checked in the delta condition above
	 */
	char last_delta_atts_values[MAX_LENGTH_REPORT_MESSAGE];
}event_based_report_context_t;


struct list_event_based_report_context_struct{
	size_t event_reports_size;
	event_based_report_context_t* event_reports;
};

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
 * Extract attributes' values and store the values in a string
 * @param packet
 * @param att_size
 * @param att_ids
 * @param message
 * @param message_size
 * @return
 */
static inline int _get_attributes_values(const ipacket_t *packet,
		const dpi_protocol_attribute_t *atts, size_t atts_size,
		char *message, size_t message_size, bool fail_if_all_empty){

	int offset = 0;
	//attributes
	attribute_t * attr_extract;
	const dpi_protocol_attribute_t *att;
	int i;
	uint32_t proto_index_in_herarchy;
	int empty_counter = 0;
	for( i=0; i<atts_size; i++ ){
		att = & atts[i];

		attr_extract = dpi_extract_attribute(packet, att);

		//separator
		if( i!=0 )
			message[offset ++] = ',';

		//special processing for IEEE_802154
		int ret = _process_ieee802154_src_dst( message+offset, message_size - offset,
				att->proto_id, att->attribute_id, attr_extract);
		offset += ret;

		//one of attributes of IEEE_802154 has been processed?
		if( ret != 0 )
			continue;

		if( attr_extract != NULL ){
			if( is_string_datatype( attr_extract->data_type ) ){
				//surround by quotes
				message[ offset ++ ] = '"';
				if( attr_extract != NULL )
					offset += mmt_attr_sprintf( message + offset, message_size - offset, attr_extract );
				message[ offset ++ ] = '"';
			}
			else
				offset += mmt_attr_sprintf( message + offset, message_size - offset, attr_extract );
		}else{
			empty_counter ++;
			//no value, use default value:
			// "" for string
			// 0  for number
			if( is_string_datatype( att->dpi_datatype )){
				message[ offset ++ ] = '"';
				message[ offset ++ ] = '"';
			}else
				message[ offset ++ ] = '0';
		}
	}

	if( fail_if_all_empty && empty_counter == atts_size )
		offset = 0;

	message[offset] = '\0';
	return offset;
}

/**
 * This callback is called by DPI when it sees one of the attributes in a event report.
 * @param packet
 * @param attribute
 * @param arg
 */
static void _event_report_handle( const ipacket_t *packet, attribute_t *attribute, void *arg ){
	event_based_report_context_t *context = (event_based_report_context_t *)arg;

	size_t i;
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset, ret;
	const event_report_conf_t *config = context->config;

	//if delta-cond is available
	if( config->delta_condition.attributes_size ){
		memset( message, 0, MAX_LENGTH_REPORT_MESSAGE );
		ret = _get_attributes_values(packet,
				config->delta_condition.attributes,
				config->delta_condition.attributes_size,
				message, MAX_LENGTH_REPORT_MESSAGE,
				true);

		//not check the delta-cond because all the attributes are not available
		if( ret == 0 )
			return;

		//check whether there are something changed
		if( memcmp(message, context->last_delta_atts_values, MAX_LENGTH_REPORT_MESSAGE ) == 0 )
			//nothing change => skip this packet
			return;

		//remember the change
		//TODO: maybe we need a hash function to store only the footprint of the message instead of store the message itself
		memcpy( context->last_delta_atts_values, message, MAX_LENGTH_REPORT_MESSAGE  );
	}

	offset = 0;
	//use the special output format that is given by user via the "output-format" parameter in .conf file
	if( config->output_format ){

		message[0] = '\0';

		for( i=0; i<config->attributes_size; i++ ){
			const dpi_protocol_attribute_t * att = & config->attributes[i];
			//prefix
			offset += append_string_without_quote( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, att->prefix );
			//value
			attribute_t * attr_extract = dpi_extract_attribute(packet, att); //get value of the attribute from the packet
			if( attr_extract != NULL )
				offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attr_extract ); //append to the message
			else {
				//no value, use default value:
				// empty for string
				// 0  for number
				if( is_string_datatype( att->dpi_datatype )){
					//nothing here
				}else
					message[ offset ++ ] = '0';
			}
			//suffix
			offset += append_string_without_quote( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, att->suffix );
			message[offset] = '\0';
		}
		//write the message as-is (without any modification) to the output channels
		output_write( context->output, config->output_channels, message );
		return;
	}

	//use the legacy output format
	//1. event id = title of the event
	offset += append_string( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, config->title );

	//separator
	message[offset] = ',';
	offset ++;

	//2. event data
	if( is_string_datatype( attribute->data_type ) ){
		//surround by quotes
		message[ offset ++ ] = '"';
		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attribute );
		message[ offset ++ ] = '"';
	}else
		offset += mmt_attr_sprintf( message + offset, MAX_LENGTH_REPORT_MESSAGE - offset, attribute );

	//separator
	message[offset] = ',';
	offset ++;

	//3. attributes data
	offset += _get_attributes_values( packet,
			config->attributes, config->attributes_size,
			&message[offset], MAX_LENGTH_REPORT_MESSAGE - offset,
			false);
	message[offset] = '\0'; //superfluous?

	output_write_report( context->output, config->output_channels,
			EVENT_REPORT_TYPE,
			&packet->p_hdr->ts, message );
}

/**
 * This function is called only 1 time on each packet once the packet is classified by DPI
 * @param context
 * @param packet
 */
void event_based_report_callback_on_receiving_packet( const ipacket_t *packet, list_event_based_report_context_t *context ){
	int i, j;
	const event_report_conf_t *cfg;
	event_based_report_context_t *rep;
	attribute_t *attr_extract;
	dpi_protocol_attribute_t *event_att;

	//no context
	if( unlikely( context == NULL ))
		return;

	for( i=0; i<context->event_reports_size; i++ ){
		rep = &context->event_reports[i];
		cfg = rep->config;;

		if( !cfg->is_enable )
			continue;
		//the event we are looking for
		event_att = cfg->event;
		attr_extract = dpi_extract_attribute(packet, event_att);

		//the event is not available => skip this report
		if( attr_extract == NULL )
			continue;

		//handle the report
		_event_report_handle( packet, attr_extract, rep );
	}
}

//Public API
list_event_based_report_context_t* event_based_report_register( mmt_handler_t *dpi_handler, const event_report_conf_t *config, size_t events_size, output_t *output ){
	int i, j;
	const event_report_conf_t *cfg;
	event_based_report_context_t *rep;

	//no event?
	list_event_based_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( list_event_based_report_context_t  ) );
	ret->event_reports_size = events_size;
	ret->event_reports = mmt_alloc_and_init_zero(  events_size * sizeof( event_based_report_context_t  ) );

	for( i=0; i<events_size; i++ ){
		cfg = &config[i];
		rep = &ret->event_reports[i];
		rep->config = cfg;

		if( !cfg->is_enable )
			continue;

		rep->output = output;

		// The event-report needs to be checked when all protocols in a packet are classified.
		// We so remove the handler function parameter to avoid be called by DPI each time it classifies the corresponding protocol
		// (for example, if the event is ip.src, the DPI can issue 2 calls if a packet has 2 IPs protocol, eg, IP in IP,
		//   consequently, the first call is inutile as there exist other protocols which does not classified)
		if( dpi_register_attribute( cfg->event, 1, dpi_handler, NULL, NULL) == 0 ){
			log_write( LOG_ERR, "Cannot register an event-based report [%s] for event [%s.%s]",
					cfg->title,
					cfg->event->proto_name,
					cfg->event->attribute_name );
			continue;
		}

		//register attribute to extract data
		dpi_register_attribute( cfg->attributes, cfg->attributes_size, dpi_handler, NULL, NULL );

		//register attribute to check condition
		dpi_register_attribute( cfg->delta_condition.attributes, cfg->delta_condition.attributes_size, dpi_handler, NULL, NULL );
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
		config = context->event_reports[i].config;
		//jump over the disable ones
		//This can create a memory leak when this event report is disable in runtime
		//(this is, it was enable at starting time but it has been disable after some time of running)
		//So, when it has been disable, one must unregister the attributes using by this event report
		if(! config->is_enable )
			continue;

		//unregister event
		dpi_unregister_attribute( config->event, 1, dpi_handler, _event_report_handle );

		//unregister attributes
		dpi_unregister_attribute( config->attributes, config->attributes_size, dpi_handler, NULL );

		//unregister attributes
		dpi_unregister_attribute( config->delta_condition.attributes, config->delta_condition.attributes_size, dpi_handler, NULL );
	}

	mmt_probe_free( context->event_reports );
	mmt_probe_free( context );
}
