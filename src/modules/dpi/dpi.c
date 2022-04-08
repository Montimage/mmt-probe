/*
 * dpi.c
 *
 *  Created on: Dec 20, 2017
 *          by: Huu Nghia
 */


#include "dpi.h"

#include <tcpip/mmt_tcpip.h>
#include "../../lib/limit.h"
#include "../../lib/malloc_ext.h"

#ifdef STAT_REPORT
#include "report/event_based_report.h"
#include "report/query_based_report.h"
#include "report/no_session_report.h"
#include "report/session_report.h"
#endif

#ifdef PCAP_DUMP_MODULE
#include "pcap_dump/pcap_dump.h"
#endif

#ifdef TCP_REASSEMBLY_MODULE
#include "reassembly/tcp_reassembly.h"
#endif

#define DPI_PACKET_HANDLER_ID 6


static inline packet_session_t * _create_session (const ipacket_t * ipacket, dpi_context_t *context){
	mmt_session_t * dpi_session = ipacket->session;

	packet_session_t *session = mmt_alloc(sizeof (packet_session_t));
	session->session_id = get_session_id( dpi_session );
	session->context    = context;

	//initialize for reporting
	IF_ENABLE_STAT_REPORT(
		session->session_stat = session_report_callback_on_starting_session( ipacket, context );
	)

	//initialize
	IF_ENABLE_HTTP_RECONSTRUCT( session->http_session = NULL );

	//attach to tcp/ip session
	set_user_session_context( dpi_session, session);
	return session;
}

////session handler========================================
/**
 * callback when starting a new session
 */
static void _starting_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	dpi_context_t *context = (dpi_context_t *) user_args;
	packet_session_t *session = dpi_get_packet_session(ipacket);

	if( session == NULL )
		_create_session (ipacket, context);
}

/**
 * callback when a session is expiring
 * It is also called for the last time when close mmt-handler
 */
static void _ending_session_handler(const mmt_session_t * dpi_session, void * user_args) {
	dpi_context_t *context = (dpi_context_t *) user_args;
	packet_session_t * session = get_user_session_context( dpi_session );

	//free http stream eventually
#ifdef HTTP_RECONSTRUCT_MODULE
	http_reconstruct_flush_session_to_file_and_free( session->http_session );
	session->http_session = NULL;
#endif

#ifdef STAT_REPORT
		//a session statistic is processed as either micro-flow or normal-flow
		bool is_micro = false;
#ifndef SIMPLE_REPORT
		if( context->micro_reports ){
			is_micro = is_micro_flow( context->micro_reports, dpi_session);
			if( is_micro )
				micro_flow_report__update( context->micro_reports, dpi_session);
		}
#endif
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
//this callback is called each time when a packet is coming
static int _packet_handler(const ipacket_t * ipacket, void * user_args) {
	dpi_context_t *context = (dpi_context_t *)user_args;
	//when packet is below to one session
	if( ipacket->session != NULL ){
		packet_session_t *session = dpi_get_packet_session(ipacket);

		IF_ENABLE_STAT_REPORT(
			if( context->probe_config->reports.session->is_enable ){
				if( session == NULL )
					session = _create_session (ipacket, context);
				session_report_callback_on_receiving_packet( ipacket, session->session_stat, context);
			}
		)
	}
	IF_ENABLE_PCAP_DUMP(
		if( context->pcap_dump )
			pcap_dump_callback_on_receiving_packet( ipacket, context->pcap_dump );
	)

	IF_ENABLE_STAT_REPORT(
		event_based_report_callback_on_receiving_packet( ipacket, context->event_reports );
		query_based_report_callback_on_receiving_packet( ipacket, context->query_reports );
	)
	return 0;
}

#ifdef TCP_REASSEMBLY_MODULE
//callback when a tcp segment is re-constructed
static void _tcp_reassembly_handler(const void *data, uint32_t payload_len, void * user_args) {
	//DEBUG("got tcp segment %"PRIu64, ipacket->packet_id );
}
#endif
/// <=== end of packet handler=============================

//This callback is called periodically when `dpi_callback_on_stat_period` is called.
//It is called for each session.
static void _period_session_report (const mmt_session_t * dpi_session, void *user_args){
	dpi_context_t    *context = (dpi_context_t *) user_args;
	packet_session_t *session = (packet_session_t *) get_user_session_context( dpi_session );

	IF_ENABLE_STAT_REPORT(
		//if session report is enable?
		if( session->session_stat ){
			//by default, this session is not considered as a micro session
			bool is_micro = false;
			//need to check if a flow is micro ???
			if( context->micro_reports )
				is_micro = is_micro_flow( context->micro_reports, dpi_session);

			//do report if the session is not a micro one
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


/**
 * This function must be called by worker periodically each x seconds( = config.stat_period )
 * @param
 */
static void _do_stat_reports( const  ms_timer_t *timer, void *args ){
	dpi_context_t *dpi_context = args;
	dpi_context->stat_periods_index ++;

	IF_ENABLE_STAT_REPORT_FULL(
		//do report for no-session protocols
		no_session_report( dpi_context->no_session_report, dpi_context->stat_periods_index );
	)

	//push DPI to perform session callback: DPI will call `_period_session_report` for each session its has
	if( dpi_context->probe_config->reports.session->is_enable )
		process_session_timer_handler( dpi_context->dpi_handler );
}

dpi_context_t* dpi_alloc_init( const probe_conf_t *config, mmt_handler_t *dpi_handler, output_t *output, uint16_t worker_index ){
	_set_default_session_timeout(config, dpi_handler);

	dpi_context_t *ret = mmt_alloc_and_init_zero( sizeof( dpi_context_t ) );
	ret->worker_index  = worker_index;
	ret->dpi_handler   = dpi_handler;
	ret->output        = output;
	ret->probe_config  = config;

	IF_ENABLE_PCAP_DUMP(
		ret->pcap_dump = pcap_dump_start( worker_index, config, dpi_handler )
	);

	IF_ENABLE_STAT_REPORT_FULL(
		ret->micro_reports = micro_flow_report_alloc_init(config->reports.microflow, output);
		ret->event_reports = event_based_report_register(dpi_handler, config->reports.events, config->reports.events_size, output);
		ret->query_reports = query_based_report_register(dpi_handler, config->reports.queries, config->reports.queries_size, output);
		ret->no_session_report = no_session_report_alloc_init(dpi_handler, output, config->is_enable_ip_fragmentation_report,
									config->is_enable_proto_no_session_report );
		ret->radius_report = radius_report_register(dpi_handler, config->reports.radius, output);
	)
	IF_ENABLE_STAT_REPORT(
		session_report_register( dpi_handler, config->reports.session, ret );


		if( config->reports.behaviour->is_enable ){
			//create another output (to file) for behaviour analysis
			//this output must use the same id as "normal" output
			ret->behaviour_output = file_output_alloc_init( config->reports.behaviour, worker_index );
		}
	)

	IF_ENABLE_LTE_REPORT(
		ret->lte_topo_report = lte_topo_report_register( dpi_handler, config->reports.session->is_gtp,
									config->reports.session->output_channels, output );

		IF_ENABLE_QOS(
				ret->lte_qos_report = lte_qos_report_register( dpi_handler, config->reports.session->is_gtp,
						config->reports.session->output_channels, output );
		)
	)

	//This callback is fired before the packets have been reordered and reassembled by mmt_reassembly
	if(! register_packet_handler( dpi_handler, DPI_PACKET_HANDLER_ID, _packet_handler, ret ) )
		ABORT( "Cannot register handler for processing packet" );

	IF_ENABLE_TCP_REASSEMBLY(
		ret->tcp_reassembly = tcp_reassembly_alloc_init(config->is_enable_tcp_reassembly, dpi_handler, _tcp_reassembly_handler, ret);
	)

	//callback when starting a new IP session
	if( config->stack_type == DLT_EN10MB
			&& config->reports.session->is_enable ){
		if( ! register_attribute_handler(dpi_handler, PROTO_IP, PROTO_SESSION, _starting_session_handler, NULL, ret ) )
			ABORT("Cannot register handler for processing a session at starting");

		if( ! register_attribute_handler(dpi_handler, PROTO_IPV6, PROTO_SESSION, _starting_session_handler, NULL, ret ) )
			ABORT("Cannot register handler for processing a session at starting");

		//callback when a session is expired
		if( !register_session_timeout_handler( dpi_handler, _ending_session_handler, ret ))
			ABORT( "Cannot register handler for processing a session at ending" );

		if( ! register_session_timer_handler( dpi_handler, _period_session_report, ret, 1) )
			ABORT( "Cannot register handler for periodically session reporting" );
	}
	IF_ENABLE_FTP_RECONSTRUCT(
		ret->data_reconstruct.ftp = ftp_reconstruct_init( config->reconstructions.ftp, dpi_handler );
	)
	IF_ENABLE_HTTP_RECONSTRUCT(
			ret->data_reconstruct.http = http_reconstruct_init( config->reconstructions.http, dpi_handler, output );
	)

	ms_timer_init( &ret->stat_timer, ret->stat_periods_index * S2MS,
			_do_stat_reports, ret );
	return ret;
}

//this happens before closing dpi_context->dpi_handler
void dpi_close( dpi_context_t *dpi_context ){
	//do the last report
	_do_stat_reports( NULL, dpi_context );
	//flush the query-reports before exit
	query_based_report_do_report( dpi_context->query_reports );

	unregister_attribute_handler(dpi_context->dpi_handler, PROTO_IP, PROTO_SESSION, _starting_session_handler );
	unregister_attribute_handler(dpi_context->dpi_handler, PROTO_IPV6, PROTO_SESSION, _starting_session_handler );

	unregister_packet_handler(dpi_context->dpi_handler, DPI_PACKET_HANDLER_ID );

	IF_ENABLE_STAT_REPORT_FULL(
		session_report_unregister(     dpi_context->dpi_handler, dpi_context->probe_config->reports.session );
		event_based_report_unregister( dpi_context->dpi_handler, dpi_context->event_reports );
		query_based_report_unregister( dpi_context->dpi_handler, dpi_context->query_reports );
		radius_report_unregister(      dpi_context->dpi_handler, dpi_context->radius_report );
	)

	IF_ENABLE_FTP_RECONSTRUCT(
		ftp_reconstruct_close( dpi_context->dpi_handler, dpi_context->data_reconstruct.ftp );
	)

	IF_ENABLE_HTTP_RECONSTRUCT(
		http_reconstruct_close( dpi_context->dpi_handler, dpi_context->data_reconstruct.http );
	)

	IF_ENABLE_TCP_REASSEMBLY( tcp_reassembly_close( dpi_context->tcp_reassembly ); )

	IF_ENABLE_LTE_REPORT(
		lte_topo_report_unregister( dpi_context->lte_topo_report );
		IF_ENABLE_QOS(
				lte_qos_report_unregister( dpi_context->lte_qos_report );
		)
	)
}

//this happens after closing dpi_context->dpi_handler
void dpi_release( dpi_context_t *dpi_context ){

	IF_ENABLE_STAT_REPORT_FULL(
		no_session_report_release(dpi_context->no_session_report );
		micro_flow_report_release( dpi_context->micro_reports );

		//if behaviour analysis output is enable
		if( dpi_context->behaviour_output != NULL ){
			file_output_release( dpi_context->behaviour_output );
		}
	)

	IF_ENABLE_PCAP_DUMP(
		pcap_dump_stop( dpi_context->pcap_dump );
	)

	IF_ENABLE_FTP_RECONSTRUCT(
		ftp_reconstruct_release( dpi_context->data_reconstruct.ftp );
	)

	IF_ENABLE_HTTP_RECONSTRUCT(
		http_reconstruct_release( dpi_context->data_reconstruct.http );
	)

	mmt_probe_free( dpi_context );
}

void dpi_update_timer( dpi_context_t *dpi_context, const struct timeval * tv){
	ms_timer_set_time( &dpi_context->stat_timer, tv);
	query_based_report_update_timer( dpi_context->query_reports, tv );
}
