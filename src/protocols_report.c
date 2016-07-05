#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip_protocols.h"
#include "processing.h"
#include <pthread.h>

void protocols_stats_iterator(uint32_t proto_id, void * args) {
	if (proto_id == 1 || proto_id == 99 ) return;
	char message[MAX_MESS + 1];
	char ip_message[MAX_MESS + 1];

	mmt_probe_context_t * probe_context = get_probe_context_config();

	struct smp_thread *th = (struct smp_thread *) args;
	proto_statistics_t * proto_stats = get_protocol_stats(th->mmt_handler, proto_id);

	while (proto_stats != NULL) {
		proto_hierarchy_t proto_hierarchy = {0};
		get_protocol_stats_path(th->mmt_handler, proto_stats, &proto_hierarchy);
		char path[128];
		proto_hierarchy_ids_to_str(&proto_hierarchy, path);
		protocol_t * proto_struct = get_protocol_struct_by_id (proto_id);
		//if (proto_struct->has_session == 0){
		int i = 0;
		//Count for fragmented and defragmented packets
		if (probe_context->enable_IP_fragmentation_report == 1){
			if (proto_id == 178 && (proto_stats->ip_frag_packets_count + proto_stats->ip_df_packets_count > 0)){
				long int ip_nodf_data_volume = (long int)(proto_stats->ip_frag_data_volume - proto_stats->ip_df_data_volume);
				long int ip_nodf_packets_count = (long int)(proto_stats->ip_frag_packets_count - proto_stats->ip_df_packets_count);
				snprintf(ip_message, MAX_MESS,
						"%u,%u,\"%s\",%lu.%lu,\"%s\",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%ld,%ld",
						101,probe_context->probe_id_number,probe_context->input_source, proto_stats->last_packet_time.tv_sec, proto_stats->last_packet_time.tv_usec,path,
						proto_stats->ip_frag_data_volume,proto_stats->ip_frag_packets_count,proto_stats->ip_df_data_volume, proto_stats->ip_df_packets_count,ip_nodf_data_volume, ip_nodf_packets_count);

				ip_message[ MAX_MESS ] = '\0';
				if (probe_context->output_to_file_enable==1)send_message_to_file_thread (ip_message,th);
				if (probe_context->redis_enable==1)send_message_to_redis ("protocol.stat", ip_message);
			}
		}
		int skip =0;
		for (i=1;i<=proto_hierarchy.len;i++){

			if (proto_hierarchy.proto_path[i] == 178 || proto_hierarchy.proto_path[i] == 182){
				skip = 1;
				reset_statistics(proto_stats);
				proto_stats = proto_stats->next;
				break;
			}
		}
		if (skip == 1) continue;
		if (proto_id == 7){
			reset_statistics(proto_stats);
			proto_stats = proto_stats->next;
			continue;
		}
		//report the stats instance if there is anything to report
		if(proto_stats->touched) {
			snprintf(message, MAX_MESS,
					"%u,%u,\"%s\",%lu.%lu,%u,\"%s\",%u,%"PRIu64",%"PRIu64",%"PRIu64",%u,%u,%u,%u,%u,%u,%lu.%lu,\"%s\",\"%s\",\"%s\",\"%s\",%u,%u,%u",
					MMT_STATISTICS_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, proto_stats->last_packet_time.tv_sec, proto_stats->last_packet_time.tv_usec, proto_id, path,
					0,proto_stats->data_volume, proto_stats->payload_volume,proto_stats->packets_count,0,0,0,
					0,0,0,proto_stats->first_packet_time.tv_sec,proto_stats->first_packet_time.tv_usec,"null","null","null","null",0,0,0);

			message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
			if (probe_context->output_to_file_enable==1)send_message_to_file_thread (message,th);
			if (probe_context->redis_enable==1)send_message_to_redis ("protocol.stat", message);
		}

		reset_statistics(proto_stats);
		proto_stats = proto_stats->next;
	}

}
