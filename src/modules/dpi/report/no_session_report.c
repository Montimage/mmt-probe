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
#include "../dpi.h"
#include "../dpi_tool.h"
#include "../../../lib/malloc_ext.h"

struct no_session_report_context_struct{
	mmt_handler_t *dpi_handler;
	output_t *output;
	const dpi_context_t *dpi_context;
	// period of the last packet processed (used when a row timestamp is not
	// found in the worker period history)
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


/* Check if this protocol stats instance is a leaf (no protocol stacked on top).
 * Returns false if any other protocol's stats has this proto_id in its hierarchy
 * at a non-terminal position (meaning something is parsed on top of it). */
static bool _is_leaf_stats(mmt_handler_t *handler, proto_statistics_t *my_stats, uint32_t my_proto_id) {
	proto_hierarchy_t my_path;
	get_protocol_stats_path(handler, my_stats, &my_path);

	for (uint32_t id = 0; id < PROTO_MAX_IDENTIFIER; id++) {
		if (id == my_proto_id) continue;

		proto_statistics_t *stats = get_protocol_stats(handler, id);
		while (stats != NULL) {
			proto_hierarchy_t path;
			get_protocol_stats_path(handler, stats, &path);

			if (path.len > my_path.len) {
				for (int j = 0; j < path.len - 1; j++) {
					if (path.proto_path[j] == (int) my_proto_id)
						return false;
				}
			}
			stats = stats->next;
		}
	}
	return true;
}

/* This function is for reporting the protocol statistics that do not have session */
static void _protocols_stats_iterator(uint32_t proto_id, void * args) {

	no_session_report_context_t *context = (no_session_report_context_t*) args;

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, proto_id );

	//printf ("report_number = %lu \n", th->report_counter);
	char proto_path_str[128];
	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int i, offset;
	proto_hierarchy_t proto_hierarchy;
	while (proto_stats != NULL) {
		if (proto_stats->touched) {
			get_protocol_stats_path( context->dpi_handler, proto_stats, &proto_hierarchy );
			dpi_proto_hierarchy_ids_to_str(&proto_hierarchy, proto_path_str, sizeof( proto_path_str ) );

			if (proto_hierarchy.len >= 3 &&
				proto_hierarchy.proto_path[proto_hierarchy.len - 1] == (int) proto_id &&
				proto_hierarchy.proto_path[proto_hierarchy.len - 2] == PROTO_ETHERNET &&
				proto_id != PROTO_ARP && // ARP now reported as session (id=100) per requirement
				_is_leaf_stats(context->dpi_handler, proto_stats, proto_id)) {

				// the row is stamped with last_packet_time: use the period of
				// that packet so all rows of one frame carry the same number
				uint32_t report_number = context->dpi_context ?
						(uint32_t) dpi_period_index_of_packet( context->dpi_context, &proto_stats->last_packet_time ) :
						context->report_number;

				offset = 0;
				STRING_BUILDER_WITH_SEPARATOR( offset, message, MAX_LENGTH_REPORT_MESSAGE, ",",
						__INT( report_number ),
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
			}
		}

		reset_statistics( proto_stats );
		proto_stats = proto_stats->next;
	}
}


//For fragmented and defragmented packets
static inline void _report_ip_frag_stat( no_session_report_context_t *context ){

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, PROTO_IP );

	char proto_path_str[128];
	char message[ MAX_LENGTH_REPORT_MESSAGE + 1 ];
	int i, offset;
	proto_hierarchy_t proto_hierarchy;
	while( proto_stats != NULL ){
		if (proto_stats->touched) {
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
		}

		proto_stats = proto_stats->next;
	}
}

/**
 * Being called periodically by #dpi_callback_on_stat_period
 * @param context
 * @return
 */
void no_session_report( no_session_report_context_t *context, const dpi_context_t *dpi_context ){
	if( context == NULL )
		return;
	context->dpi_context = dpi_context;
	context->report_number = dpi_context ? (uint32_t) dpi_context->last_packet_period_index : 0;

	if( context->is_enable_ip_fragementation_stat ){
		_report_ip_frag_stat( context );
	}
	if( context->is_enable_proto_no_session_stat )
		iterate_through_protocols( _protocols_stats_iterator, context );
}
