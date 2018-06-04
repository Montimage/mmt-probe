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
#include "../../../lib/memory.h"

struct no_session_report_context_struct{
	mmt_handler_t *dpi_handler;
	output_t *output;
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

	if (proto_id == PROTO_ETHERNET || proto_id == PROTO_META )
		return;

	no_session_report_context_t *context = (no_session_report_context_t*) args;

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, proto_id );

	//printf ("report_number = %lu \n", th->report_counter);
	char proto_path_str[128];
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int i, offset;
	proto_hierarchy_t proto_hierarchy;
	while (proto_stats != NULL) {

		get_protocol_stats_path( context->dpi_handler, proto_stats, &proto_hierarchy );

		dpi_proto_hierarchy_ids_to_str(&proto_hierarchy, proto_path_str, sizeof( proto_path_str ) );

		//DEBUG("%s", proto_path_str );
		//if (proto_struct->has_session == 0){

		//Count for fragmented and defragmented packets
		if( context->is_enable_ip_fragementation_stat ){
			if (proto_id == PROTO_IP && (proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count > 0)){
				offset = 0;
				STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_FULL_PATH_FILE_NAME, ",",
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
		}


		if( context->is_enable_proto_no_session_stat ){
			//ignore session protocol: IPv4 and IPv6, VLAN
			if( proto_id == PROTO_IP || proto_id == PROTO_IPV6 || proto_id == PROTO_8021Q)
				goto next_iteration_label;
			//ignore session protocol on top of IPv4 and IPv6
			for (i = 1; i < proto_hierarchy.len; i++){
				if (proto_hierarchy.proto_path[i] == PROTO_IP
						|| proto_hierarchy.proto_path[i] == PROTO_IPV6 )
					goto next_iteration_label;
			}

			//report the stats instance if there is anything to report
			if(proto_stats->touched) {
				offset = 0;
				STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_FULL_PATH_FILE_NAME, ",",
						__INT( proto_id ),
						__STR( proto_path_str ),
						__INT( 0 ),
						__INT( proto_stats->data_volume ),
						__INT( proto_stats->payload_volume ),
						__INT( proto_stats->packets_count ),
						__ARR( "0,0,0,0,0,0" ),
						//session initial time
						__TIME( &proto_stats->first_packet_time )
				);
				output_write_report(context->output, CONF_OUTPUT_CHANNEL_ALL,
										IP_FRAG_REPORT_TYPE, &proto_stats->last_packet_time, message);
			}
		}

		next_iteration_label:
		reset_statistics(proto_stats);
		proto_stats = proto_stats->next;
	}
}

/**
 * Being called periodically by #dpi_callback_on_stat_period
 * @param context
 * @return
 */
void no_session_report( no_session_report_context_t *context ){
	if( context == NULL || !( context->is_enable_proto_no_session_stat
			|| context->is_enable_ip_fragementation_stat ))
		return;

	iterate_through_protocols( _protocols_stats_iterator, context );
}
