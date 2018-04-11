/*
 * no_session_report.c
 *
 *  Created on: Dec 27, 2017
 *          by: Huu Nghia
 */

#include <stdint.h>
#include <string.h>
#include "header.h"

/* This function is for reporting the protocol statistics that do not have session */
static void _protocols_stats_iterator(uint32_t proto_id, void * args) {

	if (proto_id == PROTO_ETHERNET || proto_id == PROTO_META )
		return;

	dpi_context_t *context = (dpi_context_t*) args;

	bool is_enable_ip_fragementation = context->probe_config->is_enable_ip_fragementation;
	bool is_enable_proto_no_session_stat = context->probe_config->is_enable_proto_no_session_stat;

	proto_statistics_t * proto_stats = get_protocol_stats( context->dpi_handler, proto_id );

	//printf ("report_number = %lu \n", th->report_counter);
	char proto_path_str[128];
	int i;
	proto_hierarchy_t proto_hierarchy;
	while (proto_stats != NULL) {

		get_protocol_stats_path( context->dpi_handler, proto_stats, &proto_hierarchy );

		dpi_proto_hierarchy_ids_to_str(&proto_hierarchy, proto_path_str, sizeof( proto_path_str ) );

		//DEBUG("%s", proto_path_str );
		//if (proto_struct->has_session == 0){

		//Count for fragmented and defragmented packets
		if( is_enable_ip_fragementation ){
			if (proto_id == PROTO_IP && (proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count > 0)){
				output_write_report_with_format(context->output, CONF_OUTPUT_CHANNEL_ALL,
						IP_FRAG_REPORT_TYPE, &proto_stats->last_packet_time,
						"\"%s\",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64,
						proto_path_str,
						proto_stats->ip_frag_data_volume, proto_stats->ip_frag_packets_count,
						proto_stats->ip_df_data_volume,   proto_stats->ip_df_packets_count,
						(proto_stats->ip_frag_data_volume + proto_stats->ip_df_data_volume),
						(proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count));
			}
		}


		if( is_enable_proto_no_session_stat ){
			for (i = 1; i <= proto_hierarchy.len; i++){
				//ignore session protocol: IPv4 and IPv6
				if (proto_hierarchy.proto_path[i] == PROTO_IP
						|| proto_hierarchy.proto_path[i] == PROTO_IPV6 )
					goto next_iteration_label;
			}

			//reset all stats when VLAN
			if (proto_id == PROTO_8021Q )
				goto next_iteration_label;

			//report the stats instance if there is anything to report
			if(proto_stats->touched) {
				output_write_report_with_format(context->output, CONF_OUTPUT_CHANNEL_ALL,
						NON_SESSION_REPORT_TYPE, &proto_stats->last_packet_time,
						"%u,\"%s\",%u,%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,%u,%u,%lu.%06lu,\"%s\",\"%s\",\"%s\",\"%s\",%u,%u,%u",
						proto_id,
						proto_path_str,
						0,
						proto_stats->data_volume, proto_stats->payload_volume,
						proto_stats->packets_count,
						0, 0, 0,
						0, 0, 0,
						//session initial time
						proto_stats->first_packet_time.tv_sec, proto_stats->first_packet_time.tv_usec,
						"null", "null", "null", "null",
						0, 0, 0
						);

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
bool no_session_report( dpi_context_t *context ){
	if( !( context->probe_config->is_enable_proto_no_session_stat || context->probe_config->is_enable_ip_fragementation ))
		//TODO: unregister?
		return false;

	iterate_through_protocols( _protocols_stats_iterator, context );
	return true;
}
