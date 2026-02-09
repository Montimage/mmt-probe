/*
 * query_based_report.c
 *
 *  Created on: Mar 31, 2022
 *      Author: nhnghia
 */
#include <mmt_core.h>
#include <stdbool.h>
#include "../dpi_tool.h"
#include "../../output/output.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/hash.h"
#include "query_based_report.h"
#include "query/operator_stack.h"

typedef struct query_based_report_context_struct {
	const query_report_conf_t *config;
	output_t *output;
	hash_t *hash_table;
	query_operator_stack_t **group_by_operators;
	size_t ms_counter;
	struct timeval last_reported_timeval;
	size_t counter;
}query_based_report_context_t;


struct list_query_based_report_context_struct{
	size_t size;
	query_based_report_context_t* reports;
	struct timeval last_timeval;
};

static inline void _ensure_compatibility_operator_stack_arrays( const query_report_element_conf_t *att ){
	int i;
	bool b;
	const query_report_element_conf_t *el;
	query_op_type_t op;
	int datatype;
	int nb_operators = att->operators.size;
	if( nb_operators == 0 )
		return;
	//example:
	// given the stack: last(sum(diff(meta.utime)))

	//1. check data type is satisfied of the last operator that receives the proto.att
	//  => checking diff(meta.utime)
	op = att->operators.elements[ nb_operators-1 ];
	datatype = att->attribute.dpi_datatype;
	b = query_operator_can_handle( op, datatype );
	ASSERT( b == true,
			"Operator [%s] cannot handle value of %s.%s",
			query_operator_get_name(op),
			att->attribute.proto_name,
			att->attribute.attribute_name
	);

	//returned data type of diff
	datatype = query_operator_get_data_type(op, datatype);
	//2. check the upper operators in inverse order:
	// sum, last, ...
	for( i=nb_operators-2; i>=0; i-- ){
		op = att->operators.elements[ i ];
		b = query_operator_can_handle( op, datatype );
		ASSERT( b == true,
				"Operator [%s] is not compatible with result of operator [%s]",
				query_operator_get_name( op ),
				query_operator_get_name( att->operators.elements[ i+1 ] )
		);
		//output data type of the previous operator
		datatype = query_operator_get_data_type( op, datatype);
	}
}

static inline query_operator_stack_t ** _create_operator_stack_arrays( size_t size, const query_report_element_conf_t *elements ){
	int i;
	const query_report_element_conf_t *el;
	if( size == 0 )
		return NULL;
	//each stack is a pointer
	query_operator_stack_t **stacks = mmt_alloc( size * sizeof( void *));
	for( i=0; i<size; i++ ){
		el = & elements[i];
		_ensure_compatibility_operator_stack_arrays( el );
		stacks[i] = query_operator_stack_create( el->operators.size, el->operators.elements, el->attribute.dpi_datatype );
	}
	return stacks;
}

static inline bool _update_operator_stack_arrays( const ipacket_t *packet, size_t size, query_operator_stack_t **st_array,
		const query_report_element_conf_t *cfg){
	int i;
	bool b, ret = true;
	const dpi_protocol_attribute_t *att;
	attribute_t *extracted_val;
	query_operator_stack_t *st;
	for( i=0; i<size; i++ ){
		st  = st_array[i];
		att = & cfg[i].attribute;
		extracted_val = dpi_extract_attribute( packet, att);
		if( extracted_val ){
			b = query_operator_stack_add_data(st, extracted_val->data );
			ret &= b;
		}
	}
	return ret;
}

static inline void _reset_operator_stack_arrays( size_t size, query_operator_stack_t **st_array){
	int i;
	query_operator_stack_t *st;
	for( i=0; i<size; i++ ){
		st  = st_array[i];
		query_operator_stack_reset_value(st);
	}
}

static inline void _release_operator_stack_arrays( size_t size, query_operator_stack_t **st_array){
	int i;
	query_operator_stack_t *st;
	for( i=0; i<size; i++ ){
		st  = st_array[i];
		query_operator_stack_release(st);
	}
}

int _data_sprintf(char * buff, int len, int data_type, const void *data) {
	attribute_t att;
	att.data = (void*) data;
	att.data_type = data_type;
	return mmt_attr_sprintf(buff, len, &att);
}

static size_t _get_string_values( size_t message_size, char *message,
		size_t atts_size,  query_operator_stack_t **st_array ){
	query_operator_stack_t *st;
	const void *data;
	int offset = 0;
	//attributes
	int i;
	bool is_string;
	data_types_t data_type;
	for( i=0; i<atts_size; i++ ){
		st = st_array[i];

		data_type = query_operator_stack_get_data_type(st);
		data = query_operator_stack_get_value(st);

		//separator
		if( i!=0 )
			message[offset ++] = ',';

		is_string = is_string_datatype( data_type );
		if( data != NULL ){
			if( is_string )
				//surround by quotes
				message[ offset ++ ] = '"';
			offset += _data_sprintf( message + offset, message_size - offset, data_type, data );
			if( is_string )
				message[ offset ++ ] = '"';
		}else{
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

static void _query_report_handle( const ipacket_t *packet,  query_based_report_context_t *context){
	const query_report_conf_t *config = context->config;
	char message[MAX_LENGTH_REPORT_MESSAGE], *key;
	size_t key_len;
	query_operator_stack_t **select_operators;

	static int counter = 0;

	//update values of each operator in "group-by" group
	_update_operator_stack_arrays( packet, config->group_by.size, context->group_by_operators, config->group_by.elements );

	key_len = _get_string_values( MAX_LENGTH_REPORT_MESSAGE, message, config->group_by.size, context->group_by_operators );
	select_operators = hash_search( context->hash_table, key_len, (uint8_t*)message );

	//not found
	if( select_operators == NULL ){
		select_operators = _create_operator_stack_arrays( config->select.size, config->select.elements );
		key = mmt_memdup( message, key_len );
		hash_add( context->hash_table, key_len, (uint8_t*) key, select_operators);
	}

	//update values of each operator in "select" group
	_update_operator_stack_arrays( packet, config->select.size, select_operators, config->select.elements );
}

static bool _is_where_condition_valid( const ipacket_t *packet, size_t nb_attributes, const dpi_protocol_attribute_t *atts){
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
		if( packet && ! _is_where_condition_valid(packet, cfg->where.size, cfg->where.elements ) )
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
		//register attribute to extract data
		dpi_register_attribute( cfg->where.elements, cfg->where.size, dpi_handler, NULL, NULL );
		_dpi_register_attribute( cfg->group_by.elements, cfg->group_by.size, dpi_handler, NULL, NULL );
		_dpi_register_attribute( cfg->select.elements, cfg->select.size, dpi_handler, NULL, NULL );

		rep->hash_table = hash_create();
		rep->group_by_operators = _create_operator_stack_arrays( cfg->group_by.size, cfg->group_by.elements);


	}
	return ret;
}


static void _free_hash_key_and_data(size_t key_len, void *key, void *data, void *args){
	size_t select_size = *(size_t*)args;
	mmt_probe_free( key );
	query_operator_stack_t **select_operators = (query_operator_stack_t **)data;
	_release_operator_stack_arrays( select_size, select_operators );
	mmt_probe_free( select_operators );
}

static void _free_hash_table( hash_t *hash, size_t select_size ){
	hash_visit( hash, _free_hash_key_and_data, &select_size );
	hash_free( hash );
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

		_free_hash_table( rep->hash_table, config->select.size );
		_release_operator_stack_arrays( config->group_by.size, rep->group_by_operators );
		mmt_probe_free( rep->group_by_operators );
		//unregister attributes
		dpi_unregister_attribute( config->where.elements, config->where.size, dpi_handler, NULL );
		_dpi_unregister_attribute( config->group_by.elements, config->group_by.size, dpi_handler, NULL );
		_dpi_unregister_attribute( config->select.elements, config->select.size, dpi_handler, NULL );
	}

	mmt_probe_free( context->reports );
	mmt_probe_free( context );
}

static void _flush_reports_then_reset( query_based_report_context_t *rep, const struct timeval *tv ){
	const query_report_conf_t *config = rep->config;
	char message[MAX_LENGTH_REPORT_MESSAGE], *p;
	query_operator_stack_t **select_operators;
	size_t i;
	hash_item_t *it;
	size_t select_size = config->select.size;
	//do report
	hash_t *hash = rep->hash_table;
	size_t message_size = MAX_LENGTH_REPORT_MESSAGE - 1;

	rep->counter ++;

	//the 2 first elements of reports: title, order
	i = snprintf(message, message_size, "\"%s\",%zu,", config->title, rep->counter );
	message_size -= i;
	p = message + i;
	for( i=0; i<hash->capability; i++ ){
		it = &hash->items[i];
		if( ! it->is_occupy )
			continue;
		select_operators = (query_operator_stack_t **) it->data;
		//fill the rest to message
		_get_string_values( message_size, p, select_size, select_operators );

		output_write_report( rep->output, config->output_channels,
				QUERY_REPORT_TYPE, tv, message );

		//free key and data
		mmt_probe_free( it->key );
		_release_operator_stack_arrays( select_size, select_operators );
		mmt_probe_free( select_operators );
		it->is_occupy = false;
	}
	rep->last_reported_timeval.tv_sec  = tv->tv_sec;
	rep->last_reported_timeval.tv_usec = tv->tv_usec;
}

void query_based_report_do_report( list_query_based_report_context_t *context ){
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

		_flush_reports_then_reset( rep, &context->last_timeval );
	}
}

//1 second = 1M microsecond
#define S2US  1000000
//1 millisecond = 1K microseconds
#define MS2US    1000
static size_t _ms_diff( const struct timeval *start, const struct timeval *end ){
	size_t us1 = start->tv_sec * S2US + start->tv_usec;
	size_t us2 = end->tv_sec * S2US + end->tv_usec;
	if( us1 >= us2 )
		return 0;
	return (us2 - us1) / MS2US;
}

void query_based_report_update_timer( list_query_based_report_context_t *context, const struct timeval *tv ){
	int i;
	const query_report_conf_t *config;
	query_based_report_context_t *rep;
	size_t ms;

	if( context == NULL )
		return;

	//remember the timestamp value that will be used to write the report before exiting MMT-Probe
	context->last_timeval.tv_sec  = tv->tv_sec;
	context->last_timeval.tv_usec = tv->tv_usec;

	for( i=0; i<context->size; i++ ){
		rep = &context->reports[i];
		config = context->reports[i].config;
		//jump over the disable ones
		//This can create a memory leak when this event report is disable in runtime
		//(this is, it was enable at starting time but it has been disable after some time of running)
		//So, when it has been disable, one must unregister the attributes using by this event report
		if(! config->is_enable )
			continue;

		ms = _ms_diff( &rep->last_reported_timeval, tv );
		if( ms < config->ms_period )
			continue;

		_flush_reports_then_reset( rep, tv );
	}
}
