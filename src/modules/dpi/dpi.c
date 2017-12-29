/*
 * flow_stat.c
 *
 *  Created on: Dec 20, 2017
 *      Author: nhnghia
 */

#include "header.h"

//header
//event-based report
void event_based_report_unregister( dpi_context_t *dpi_context  );
void event_based_report_register( dpi_context_t *dpi_context );
//no-session protocol report
bool no_session_report( dpi_context_t *context );

//session protocols report
bool session_report_register( dpi_context_t *context );


dpi_context_t* dpi_alloc_init( const probe_conf_t *config, mmt_handler_t *mmt_dpi, output_t *output, uint16_t worker_index ){

	//set timeouts
	set_default_session_timed_out( mmt_dpi, config->session_timeout->default_session_timeout );
	set_long_session_timed_out(    mmt_dpi, config->session_timeout->long_session_timeout  );
	set_short_session_timed_out(   mmt_dpi, config->session_timeout->short_session_timeout );
	set_live_session_timed_out(    mmt_dpi, config->session_timeout->live_session_timeout  );

	dpi_context_t *ret = alloc( sizeof( dpi_context_t ) );
	ret->worker_index  = worker_index;
	ret->dpi_handler   = mmt_dpi;
	ret->output        = output;
	ret->probe_config  = config;
	ret->event_based_context = NULL;


	event_based_report_register( ret );

	session_report_register( ret );

	//if(  )

	return ret;
}


void dpi_release( dpi_context_t *dpi_context ){
	//last report of no-session
	no_session_report( dpi_context );

	event_based_report_unregister( dpi_context );
	xfree( dpi_context );
}


/**
 * This function must be called by worker periodically each x seconds( = config.stat_period )
 * @param
 */
void dpi_callback_on_stat_period( dpi_context_t *dpi_context){

	no_session_report( dpi_context );

	//push SDK to perform session callback
	if( dpi_context->probe_config->reports.session->is_enable )
		process_session_timer_handler( dpi_context->dpi_handler );
}
