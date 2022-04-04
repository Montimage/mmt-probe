/*
 * query_based_report.c
 *
 *  Created on: Mar 31, 2022
 *      Author: nhnghia
 */
#include <mmt_core.h>
#include "../dpi_tool.h"
#include "../../output/output.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/hash.h"
#include "query_based_report.h"
#include "query/operator.h"

typedef struct query_based_report_context_struct {
	const query_report_conf_t *config;
	output_t *output;
	hash_t *hash_table;
}query_based_report_context_t;


struct list_query_based_report_context_struct{
	size_t size;
	query_based_report_context_t* reports;
};

static inline bool _update_attribute( const ipacket_t *packet, query_report_element_conf_t *cfg ){
	attribute_t * attr_extract = dpi_extract_attribute(packet, & cfg->attribute);
	const void *data = attr_extract->data;
	query_operator_t *op;
	int i;
	bool b;
	//normally do no need to check, as this size does not change in runtime
	if( cfg->operators.size == 0 )
		return false;

	//back trace
	for( i=cfg->operators.size-1; i>=0; i++ ){
		op = cfg->operators.elements[i];
		b = query_operator_add_data( op, data );
		if( b == false )
			return false;
		data = query_operator_get_value( op );
	}
	return true;
}

static inline bool _update_attributes( const ipacket_t *packet, query_report_element_conf_t *cfg, size_t size ){
	int i;
	bool ret = true;
	for( i=0; i<size; i++ )
		ret = ret && _update_attribute( packet, &cfg[i] );
	return false;
}

int _data_sprintf(char * buff, int len, int data_type, const void *data) {
	attribute_t att;
	att.data = data;
	att.data_type = data_type;
	return mmt_attr_sprintf(buff, len, &att);
}

static size_t _get_string_values( size_t message_size, char *message,
		query_report_element_conf_t *atts, size_t atts_size  ){
	const query_report_element_conf_t *att;
	const void *data;
	int offset = 0;
	//attributes
	int i;
	bool is_string;
	int empty_counter = 0;
	for( i=0; i<atts_size; i++ ){
		att = & atts[i];

		data = query_operator_get_value( att->operators.elements[0] );

		//separator
		if( i!=0 )
			message[offset ++] = ',';

		is_string = is_string_datatype( att->attribute.dpi_datatype );
		if( data != NULL ){
			if( is_string )
				//surround by quotes
				message[ offset ++ ] = '"';
			offset += _data_sprintf( message + offset, message_size - offset,
					att->attribute.dpi_datatype, data );
			if( is_string )
				message[ offset ++ ] = '"';
		}else{
			empty_counter ++;
			//no value, use default value:
			// "" for string
			// 0  for number
			if( is_string ){
				message[ offset ++ ] = '"';
				message[ offset ++ ] = '"';
			}else
				message[ offset ++ ] = '0';
		}
	}
	message[offset] = '\0';
	return offset;
}

static query_report_element_conf_t *_duplicate_attributes( size_t size, const query_report_element_conf_t *org ){
	query_report_element_conf_t *ret = mmt_alloc( size * sizeof(query_report_element_conf_t) );
	int i, j;
	for( i=0; i<size; i++ ){
		ret[i] = org[i];
		for( j=0; j<ret[i].operators.size; j++ )
			ret[i].operators.elements[j] = query_operator_duplicate( org[i].operators.elements[j] );
	}
	return ret;
}

static void _query_report_handle( const ipacket_t *packet,  query_based_report_context_t *context){
	const query_report_conf_t *config = context->config;
	char message[MAX_LENGTH_REPORT_MESSAGE], *key;
	size_t key_len;
	size_t atts_size = config->select.size;
	query_report_element_conf_t *atts;

	static int counter = 0;

	//update values of each operator in "group-by" and "select" groupes
	_update_attributes( packet, config->group_by.elements, config->group_by.size );

	key_len = _get_string_values( MAX_LENGTH_REPORT_MESSAGE, message, config->group_by.elements, config->group_by.size );
	atts = hash_search( context->hash_table, key_len, (uint8_t*)message );

	//not found
	if( atts == NULL ){
		atts = _duplicate_attributes( atts_size, config->select.elements );
		key = mmt_memdup( message, key_len );
		hash_add( context->hash_table, key_len, (uint8_t*) key, atts);
	}

	_update_attributes( packet, atts, atts_size );

	if( counter ++ == 10 ){
		printf("%s,", message );
		_get_string_values( MAX_LENGTH_REPORT_MESSAGE, message, atts, atts_size );
		printf("%s\n", message );
	}

}

static bool _is_where_condition_ok( const ipacket_t *packet, size_t nb_attributes, const dpi_protocol_attribute_t *atts){
	int i;
	for( i=0; i<nb_attributes; i++ )
		if( dpi_extract_attribute(packet, &atts[i]) == NULL )
			return false;
	return true;
}

void query_based_report_callback_on_receiving_packet( const ipacket_t *packet, list_query_based_report_context_t *context ){
	int i, j;
	const query_report_conf_t *cfg;
	query_based_report_context_t *rep;

	//no context
	if( unlikely( context == NULL ))
		return;

	//for each report
	for( i=0; i<context->size; i++ ){
		rep = &context->reports[i];
		cfg = rep->config;;

		if( !cfg->is_enable )
			continue;

		//the events in WHERE are not available => skip this report
		if( packet && ! _is_where_condition_ok(packet, cfg->where.size, cfg->where.elements ) )
			continue;

		//handle the report
		_query_report_handle( packet, rep );
	}
}

static inline int _dpi_unregister_attribute( const query_report_element_conf_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct ){
	int i, ret = 0;
	uint32_t proto_id, att_id;
	for( i=0; i<count; i++ ){
		proto_id = atts[i].attribute.proto_id;
		att_id   = atts[i].attribute.attribute_id;
		if( proto_id == 0 || att_id == 0 )
			continue;

		//register without handler function
		if( handler_fct == NULL ){
			if( is_registered_attribute( dpi_handler, proto_id, att_id) ){
				if( ! unregister_extraction_attribute( dpi_handler, proto_id, att_id) )
					log_write( LOG_WARNING, "Cannot unregister attribute [%s.%s]",
							atts[i].attribute.proto_name,
							atts[i].attribute.attribute_name
					);
			else
				ret ++;
			}
		}else{
			if( is_registered_attribute_handler( dpi_handler, proto_id, att_id, handler_fct ) ){
				if( !unregister_attribute_handler( dpi_handler, proto_id, att_id, handler_fct))
					log_write( LOG_ERR, "Cannot register handler for [%s.%s]",
						atts[i].attribute.proto_name,
						atts[i].attribute.attribute_name );
			else
				ret ++;
			}
		}
	}
	return ret;
}

static inline int _dpi_register_attribute( query_report_element_conf_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct, void *args ){
	dpi_protocol_attribute_t *att;
	int i, ret = 0;
	for( i=0; i<count; i++ ){
		att = &atts[i].attribute;
		if( ! dpi_load_proto_id_and_att_id( att ) ){
			log_write( LOG_ERR, "Does not support protocol [%s] with its attribute [%s]",
					att->proto_name,
					att->attribute_name);
			continue;
		}

		//register without handler function
		if( handler_fct == NULL ){
			if( ! register_extraction_attribute( dpi_handler, att->proto_id, att->attribute_id) )
				log_write( LOG_WARNING, "Cannot register attribute [%s.%s]",
						att->proto_name,
						att->attribute_name
				);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler, att->proto_id, att->attribute_id, handler_fct, NULL, args ) ){
				log_write( LOG_ERR, "Cannot register handler for [%s.%s]",
						att->proto_name,
						att->attribute_name );
			}
			else
				ret ++;
		}
	}
	return ret;
}

//Public API
list_query_based_report_context_t* query_based_report_register( mmt_handler_t *dpi_handler,
		const query_report_conf_t *config, size_t events_size, output_t *output ){
	int i, j;
	const query_report_conf_t *cfg;
	query_based_report_context_t *rep;

	//no event?
	list_query_based_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( list_query_based_report_context_t  ) );
	ret->size = events_size;
	ret->reports = mmt_alloc_and_init_zero(  events_size * sizeof( query_based_report_context_t  ) );

	for( i=0; i<events_size; i++ ){
		cfg = &config[i];
		rep = &ret->reports[i];
		rep->config = cfg;

		if( !cfg->is_enable )
			continue;

		rep->output = output;
		rep->hash_table = hash_create();

		//register attribute to extract data
		dpi_register_attribute( cfg->where.elements, cfg->where.size, dpi_handler, NULL, NULL );
		_dpi_register_attribute( cfg->group_by.elements, cfg->group_by.size, dpi_handler, NULL, NULL );
		_dpi_register_attribute( cfg->select.elements, cfg->select.size, dpi_handler, NULL, NULL );
	}
	return ret;
}

//Public API
void query_based_report_unregister( mmt_handler_t *dpi_handler, list_query_based_report_context_t *context  ){
	int i;
	const query_report_conf_t *config;
	query_based_report_context_t *rep;
	if( context == NULL )
		return;

	for( i=0; i<context->size; i++ ){
		rep = &context->reports[i];
		config = context->reports[i].config;
		//jump over the disable ones
		//This can create a memory leak when this event report is disable in runtime
		//(this is, it was enable at starting time but it has been disable after some time of running)
		//So, when it has been disable, one must unregister the attributes using by this event report
		if(! config->is_enable )
			continue;

		hash_free( rep->hash_table );
		//unregister attributes
		dpi_unregister_attribute( config->where.elements, config->where.size, dpi_handler, NULL );
		_dpi_unregister_attribute( config->group_by.elements, config->group_by.size, dpi_handler, NULL );
		_dpi_unregister_attribute( config->select.elements, config->select.size, dpi_handler, NULL );
	}

	mmt_probe_free( context->reports );
	mmt_probe_free( context );
}
