/*
 * no_session_report.c
 *
 *  Created on: Dec 27, 2017
 *          by: Huu Nghia
 */

#include <stdint.h>
#include <string.h>

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>


#include "no_session_report.h"
#include "../dpi_tool.h"
#include "../../../lib/malloc_ext.h"

struct no_session_report_context_struct{
	mmt_handler_t *dpi_handler;
	output_t *output;
	uint32_t report_number;
	bool is_enable_ip_fragementation_stat;
	bool is_enable_proto_no_session_stat;
};

no_session_report_context_t* no_session_report_alloc_init( mmt_handler_t *dpi_handler, output_t *output,
		bool is_enable_ip_fragementation_report,  bool is_enable_proto_no_session_stat){
	if( !is_enable_ip_fragementation_report && !is_enable_proto_no_session_stat )
		return NULL;

	no_session_report_context_t *ret = mmt_alloc( sizeof( no_session_report_context_t ));
	ret->dpi_handler = dpi_handler;
	ret->output = output;
	ret->is_enable_ip_fragementation_stat = is_enable_ip_fragementation_report;
	ret->is_enable_proto_no_session_stat = is_enable_proto_no_session_stat;

	int val = 0;
	if( is_enable_ip_fragementation_report ){
		val &= register_extraction_attribute( dpi_handler, PROTO_IP, IP_FRAG_PACKET_COUNT);
		val &= register_extraction_attribute( dpi_handler, PROTO_IP, IP_FRAG_DATA_VOLUME);
		val &= register_extraction_attribute( dpi_handler, PROTO_IP, IP_DF_PACKET_COUNT);
		val &= register_extraction_attribute( dpi_handler, PROTO_IP, IP_DF_DATA_VOLUME);

		if( val )
			ABORT( "Cannot register protocols and attributes for IP fragmentation report" );
	}

	return ret;
}

void no_session_report_release( no_session_report_context_t *context ){
	mmt_probe_free( context );
}


/* This function is for reporting the protocol statistics that do not have session */
static void _protocols_stats_iterator(uint32_t proto_id, void * args) {
	//do statistic only for no-ip protocol
	switch( proto_id ){
	case PROTO_ARP:
		break;
	default:
		return;
	}

	no_session_report_context_t *context = (no_session_report_context_t*) args;

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, proto_id );

	//printf ("report_number = %lu \n", th->report_counter);
	char proto_path_str[128];
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int i, offset;
	proto_hierarchy_t proto_hierarchy;
	while (proto_stats != NULL) {
		//the statistics have been updated since the last reset
		if( ! proto_stats->touched )
			goto next_iteration_label;

		get_protocol_stats_path( context->dpi_handler, proto_stats, &proto_hierarchy );
		dpi_proto_hierarchy_ids_to_str(&proto_hierarchy, proto_path_str, sizeof( proto_path_str ) );

		//report the stats instance
		offset = 0;
		STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_REPORT_MESSAGE, ",",
				__INT( context->report_number ),
				__INT( proto_id ),
				__STR( proto_path_str ),
				__INT( 0 ), //Nb active flows
				__INT( proto_stats->data_volume ),
				__INT( proto_stats->payload_volume ),
				__INT( proto_stats->packets_count ),
				__ARR( "0,0,0,0,0,0" ),
				//session initial time
				__TIME( &proto_stats->first_packet_time )
		);
		output_write_report(context->output, CONF_OUTPUT_CHANNEL_ALL,
				NON_SESSION_REPORT_TYPE, &proto_stats->last_packet_time, message);

		next_iteration_label:
		reset_statistics( proto_stats );
		proto_stats = proto_stats->next;
	}
}


//For fragmented and defragmented packets
static inline void _report_ip_frag_stat( no_session_report_context_t *context ){

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, PROTO_IP );

	char proto_path_str[128];
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int i, offset;
	proto_hierarchy_t proto_hierarchy;
	while( proto_stats != NULL ){
		if( ! proto_stats->touched )
			goto _next_frag_iteration_label;

		get_protocol_stats_path( context->dpi_handler, proto_stats, &proto_hierarchy );

		dpi_proto_hierarchy_ids_to_str(&proto_hierarchy, proto_path_str, sizeof( proto_path_str ) );

		if ( proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count > 0){
			offset = 0;
			STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_REPORT_MESSAGE, ",",
					__STR( proto_path_str ),
					__INT( proto_stats->ip_frag_data_volume ),
					__INT( proto_stats->ip_frag_packets_count ),
					__INT( proto_stats->ip_df_data_volume ),
					__INT( proto_stats->ip_df_packets_count ),
					__INT( (proto_stats->ip_frag_data_volume + proto_stats->ip_df_data_volume) ),
					__INT( (proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count) )
			);
			output_write_report(context->output, CONF_OUTPUT_CHANNEL_ALL,
					IP_FRAG_REPORT_TYPE, &proto_stats->last_packet_time, message );
		}

		//reset ip_frag_data
		proto_stats->ip_df_data_volume     = 0;
		proto_stats->ip_df_packets_count   = 0;
		proto_stats->ip_frag_data_volume   = 0;
		proto_stats->ip_frag_packets_count = 0;

		_next_frag_iteration_label:
		proto_stats = proto_stats->next;
	}
}

/**
 * Being called periodically by #dpi_callback_on_stat_period
 * @param context
 * @return
 */
void no_session_report( no_session_report_context_t *context, uint32_t report_number ){
	if( context == NULL )
		return;
	context->report_number = report_number;

	if( context->is_enable_ip_fragementation_stat ){
		_report_ip_frag_stat( context );
	}
	if( context->is_enable_proto_no_session_stat )
		iterate_through_protocols( _protocols_stats_iterator, context );
}
