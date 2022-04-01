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
#include "query_based_report.h"
#include "query/operator.h"

typedef struct query_based_report_context_struct {
	const query_report_conf_t *config;
	output_t *output;
}query_based_report_context_t;


struct list_query_based_report_context_struct{
	size_t size;
	query_based_report_context_t* reports;
};

static void _query_report_handle( const ipacket_t *packet,  query_based_report_context_t *context){

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
		if( ! _is_where_condition_ok(packet, cfg->where.size, cfg->where.elements ) )
			continue;

		//handle the report
		_query_report_handle( packet, rep );
	}
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
		dpi_register_attribute( cfg->group_by.elements, cfg->group_by.size, dpi_handler, NULL, NULL );
	}
	return ret;
}

//Public API
void query_based_report_unregister( mmt_handler_t *dpi_handler, list_query_based_report_context_t *context  ){
	int i;
	const query_report_conf_t *config;
	if( context == NULL )
		return;

	for( i=0; i<context->size; i++ ){
		config = context->reports[i].config;
		//jump over the disable ones
		//This can create a memory leak when this event report is disable in runtime
		//(this is, it was enable at starting time but it has been disable after some time of running)
		//So, when it has been disable, one must unregister the attributes using by this event report
		if(! config->is_enable )
			continue;

		//unregister attributes
		//dpi_unregister_attribute( config->select.elements, config->select.size, dpi_handler, NULL );
		dpi_unregister_attribute( config->where.elements, config->where.size, dpi_handler, NULL );
		dpi_unregister_attribute( config->group_by.elements, config->group_by.size, dpi_handler, NULL );
	}

	mmt_probe_free( context->reports );
	mmt_probe_free( context );
}
