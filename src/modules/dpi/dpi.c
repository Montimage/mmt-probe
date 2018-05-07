/*
 * flow_stat.c
 *
 *  Created on: Dec 20, 2017
 *          by: Huu Nghia
 */


#include "dpi.h"

#include <tcpip/mmt_tcpip.h>
#include "../../lib/memory.h"
#include "../../lib/limit.h"

#ifdef STAT_REPORT
#include "report/event_based_report.h"
#include "report/no_session_report.h"
#include "report/session_report.h"
#endif

#ifdef PCAP_DUMP_MODULE
#include "pcap_dump/pcap_dump.h"
#endif

#define DPI_PACKET_HANDLER_ID 6

static inline packet_session_t * _create_session (const ipacket_t * ipacket, dpi_context_t *context){
	mmt_session_t * dpi_session = ipacket->session;

	packet_session_t *session = mmt_alloc(sizeof (packet_session_t));
	session->session_id = get_session_id( dpi_session );

	IF_ENABLE_STAT_REPORT(
		session->session_stat = session_report_callback_on_starting_session( ipacket );
	)

	set_user_session_context( dpi_session, session);
	return session;
}

////session handler========================================
//callback when starting a new session
static void _starting_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	dpi_context_t *context = (dpi_context_t *) user_args;
	packet_session_t *session = (packet_session_t *) get_user_session_context_from_packet(ipacket);

	if( session == NULL )
		session = _create_session (ipacket, context);
}
//callback when a session is expiring
static void _ending_session_handler(const mmt_session_t * dpi_session, void * user_args) {
	dpi_context_t *context = (dpi_context_t *) user_args;
	packet_session_t * session = get_user_session_context( dpi_session );

#ifdef STAT_REPORT
		//a session statistic is processed as either micro-flow or normal-flow
		bool is_micro = false;
		if( context->micro_reports ){
			is_micro = is_micro_flow( context->micro_reports, dpi_session);
			if( is_micro )
				micro_flow_report__update( context->micro_reports, dpi_session);
		}

		if( context->probe_config->reports.session->is_enable ){
			//do statistic only if the session is not micro one
			if( ! is_micro  )
				session_report_do_report(dpi_session, session->session_stat, context);

			//we always need to free session as it was created when starting a new session (at that moment, we haven't known yet it is micro- or normal-flow)
			session_report_callback_on_ending_session( dpi_session, session->session_stat, context );
		}
#endif

	mmt_probe_free( session );
}
/// <=== end of session handler============================

/// packet handler=========================================
//callback when a packet is coming
static int _packet_handler(const ipacket_t * ipacket, void * user_args) {
	dpi_context_t *context = (dpi_context_t *)user_args;

	//when packet is below to one session
	if( ipacket->session != NULL ){
		packet_session_t *session = (packet_session_t *) get_user_session_context_from_packet(ipacket);

		if( session == NULL )
			session = _create_session (ipacket, context);

		IF_ENABLE_PCAP_DUMP(
			if( context->pcap_dump != NULL)
				pcap_dump_callback_on_receiving_packet( ipacket, context->pcap_dump );
		)

		IF_ENABLE_STAT_REPORT(
			if( context->probe_config->reports.session->is_enable )
				session_report_callback_on_receiving_packet( ipacket, session->session_stat );
		)
	}
	return 0;
}
/// <=== end of packet handler=============================


static void _period_session_report (const mmt_session_t * dpi_session, void *user_args){
	dpi_context_t    *context = (dpi_context_t *) user_args;
	packet_session_t *session = (packet_session_t *) get_user_session_context( dpi_session );

	IF_ENABLE_STAT_REPORT(
		bool is_micro = false;
		//if session report is enable?
		if( session->session_stat ){
			//need to check if a flow is micro ???
			if( context->micro_reports )
				is_micro = is_micro_flow( context->micro_reports, dpi_session);

			//do report if the flow is not micro
			if( !is_micro )
				session_report_do_report( dpi_session, session->session_stat, context );
		}
	)
}


static inline void _set_default_session_timeout( const probe_conf_t *config, mmt_handler_t *mmt_dpi ){
	//set timeouts
	set_default_session_timed_out( mmt_dpi, config->session_timeout->default_session_timeout );
	set_long_session_timed_out(    mmt_dpi, config->session_timeout->long_session_timeout  );
	set_short_session_timed_out(   mmt_dpi, config->session_timeout->short_session_timeout );
	set_live_session_timed_out(    mmt_dpi, config->session_timeout->live_session_timeout  );
}

dpi_context_t* dpi_alloc_init( const probe_conf_t *config, mmt_handler_t *dpi_handler, output_t *output, uint16_t worker_index ){
	_set_default_session_timeout(config, dpi_handler);

	dpi_context_t *ret = mmt_alloc_and_init_zero( sizeof( dpi_context_t ) );
	ret->worker_index  = worker_index;
	ret->dpi_handler   = dpi_handler;
	ret->output        = output;
	ret->probe_config  = config;

	IF_ENABLE_PCAP_DUMP(
		if( config->reports.pcap_dump->is_enable )
			ret->pcap_dump = pcap_dump_start( worker_index, config->reports.pcap_dump, dpi_handler )
	);

	IF_ENABLE_STAT_REPORT(
		ret->micro_reports = micro_flow_report_alloc_init(config->reports.microflow, output);
		ret->event_reports = event_based_report_register(dpi_handler, config->reports.events, config->reports.events_size, output);
		ret->no_session_report = no_session_report_alloc_init(dpi_handler, output, config->is_enable_ip_fragementation_report, config->is_enable_proto_no_session_report );

		session_report_register( dpi_handler, config->reports.session );

		ret->radius_report = radius_report_register(dpi_handler, config->reports.radius, output);
	)

	if(! register_packet_handler( dpi_handler, DPI_PACKET_HANDLER_ID, _packet_handler, ret ) )
		ABORT( "Cannot register handler for processing packet" );

	//callback when starting a new IP session
	if( ! register_attribute_handler(dpi_handler, PROTO_IP, PROTO_SESSION, _starting_session_handler, NULL, ret ) )
		ABORT("Cannot register handler for processing a session at starting");

	if( ! register_attribute_handler(dpi_handler, PROTO_IPV6, PROTO_SESSION, _starting_session_handler, NULL, ret ) )
		ABORT("Cannot register handler for processing a session at starting");

	//callback when a session is expired
	if( !register_session_timeout_handler( dpi_handler, _ending_session_handler, ret ))
		ABORT( "Cannot register handler for processing a session at ending" );

	if( ! register_session_timer_handler( dpi_handler, _period_session_report, ret) )
		ABORT( "Cannot register handler for periodically session reporting" );

	return ret;
}

//this happens before closing dpi_context->dpi_handler
void dpi_close( dpi_context_t *dpi_context ){
	unregister_attribute_handler(dpi_context->dpi_handler, PROTO_IP, PROTO_SESSION, _starting_session_handler );
	unregister_attribute_handler(dpi_context->dpi_handler, PROTO_IPV6, PROTO_SESSION, _starting_session_handler );

	unregister_packet_handler(dpi_context->dpi_handler, DPI_PACKET_HANDLER_ID );

	IF_ENABLE_STAT_REPORT(
		session_report_unregister( dpi_context->dpi_handler, dpi_context->probe_config->reports.session );
		event_based_report_unregister( dpi_context->event_reports );
		radius_report_unregister( dpi_context->radius_report );
	)
}

//this happens after closing dpi_context->dpi_handler
void dpi_release( dpi_context_t *dpi_context ){
	IF_ENABLE_STAT_REPORT(
		no_session_report_release(dpi_context->no_session_report );
		micro_flow_report_release( dpi_context->micro_reports );
	)

	IF_ENABLE_PCAP_DUMP(
		if( dpi_context->probe_config->reports.pcap_dump->is_enable )
			pcap_dump_stop( dpi_context->pcap_dump );
	)

	mmt_probe_free( dpi_context );
}


/**
 * This function must be called by worker periodically each x seconds( = config.stat_period )
 * @param
 */
void dpi_callback_on_stat_period( dpi_context_t *dpi_context){
	dpi_context->stat_periods_index ++;

	IF_ENABLE_STAT_REPORT(
		//do report for no-session protocols
		no_session_report( dpi_context->no_session_report );
	)

	//push SDK to perform session callback
	if( dpi_context->probe_config->reports.session->is_enable )
		process_session_timer_handler( dpi_context->dpi_handler );
}
