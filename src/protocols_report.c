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

void protocols_stats_iterator(uint32_t proto_id, void * args) {
    //FILE * out_file = (probe_context->data_out_file != NULL) ? probe_context->data_out_file : stdout;
    char message[MAX_MESS + 1];
    mmt_handler_t * mmt_handler = (mmt_handler_t *) args;
    mmt_probe_context_t * probe_context = get_probe_context_config();

    if (proto_id <= 1) return; //ignor META and UNknown protocols
    proto_statistics_t * proto_stats = get_protocol_stats(mmt_handler, proto_id);
    proto_hierarchy_t proto_hierarchy = {0};
    struct timeval ts = get_last_activity_time(mmt_handler);

    //ethernet_statistics_t * eth_stat = (ethernet_statistics_t *) malloc (sizeof(ethernet_statistics_t));
    //memset(eth_stat, '\0', sizeof (ethernet_statistics_t));

    while (proto_stats != NULL) {

        get_protocol_stats_path(mmt_handler, proto_stats, &proto_hierarchy);
        char path[128];
        //proto_hierarchy_to_str(&proto_hierarchy, path);
        proto_hierarchy_ids_to_str(&proto_hierarchy, path);
        /*
        proto_statistics_t children_stats = {0};
        get_children_stats(proto_stats, & children_stats);
        if ((children_stats.packets_count != 0) && ((proto_stats->packets_count - children_stats.packets_count) != 0)) {
            //The stats instance has children, report the global stats first
            fprintf(out_file, "%u,%lu.%lu,%u,%s,%u,"
                    "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", MMT_STATISTICS_REPORT_FORMAT, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 0,
                    proto_stats->sessions_count - proto_stats->timedout_sessions_count,
                    proto_stats->data_volume, proto_stats->payload_volume, proto_stats->packets_count);

            fprintf(out_file, "%u,%lu.%lu,%u,%s,%u,"
                    "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", MMT_STATISTICS_REPORT_FORMAT, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 1,
                    (proto_stats->sessions_count)?(proto_stats->sessions_count - proto_stats->timedout_sessions_count) - (children_stats.sessions_count - children_stats.timedout_sessions_count):0,
                    proto_stats->data_volume - children_stats.data_volume,
                    proto_stats->payload_volume - children_stats.payload_volume,
                    proto_stats->packets_count - children_stats.packets_count);
        } else {
            fprintf(out_file, "%u,%lu.%lu,%u,%s,%u,"
                    "%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64"\n", MMT_STATISTICS_REPORT_FORMAT, ipacket->p_hdr->ts.tv_sec, ipacket->p_hdr->ts.tv_usec, proto_id, path, 1,
                    proto_stats->sessions_count - proto_stats->timedout_sessions_count,
                    proto_stats->data_volume, proto_stats->payload_volume, proto_stats->packets_count);
        }
         */
        //report the stats instance if there is anything to report
        if(proto_stats->touched) {
            /*
	    	if (proto_id==99){
	    	    eth_stat->payload_volume_direction[0]=total_inbound;
	    	    eth_stat->payload_volume_direction[1]=total_outbound;
	    	    eth_stat->total_inbound_packet_count=total_inbound_packet_count;
	    	    eth_stat->total_outbound_packet_count=total_outbound_packet_count;

	    	}
             */
            snprintf(message, MAX_MESS,
                    "%u,%u,\"%s\",%lu.%lu,%u,\"%s\",%"PRIu64",%"PRIi64",%"PRIi64",%"PRIu64"",
                    MMT_STATISTICS_REPORT_FORMAT, probe_context->probe_id_number, probe_context->input_source, ts.tv_sec, ts.tv_usec, proto_id, path,
                    proto_stats->sessions_count,proto_stats->data_volume, proto_stats->payload_volume,proto_stats->packets_count);

            message[ MAX_MESS ] = '\0'; // correct end of string in case of truncated message
            if (probe_context->output_to_file_enable==1)send_message_to_file (message);
            if (probe_context->redis_enable==1)send_message_to_redis ("protocol.stat", message);
            /*
            fprintf(out_file, "%u,%lu.%lu,%u,%s,"
                "%"PRIu64",%"PRIi64",%"PRIu64",%"PRIu64",%"PRIu64"\n", MMT_STATISTICS_REPORT_FORMAT, ts.tv_sec, ts.tv_usec, proto_id, path,
                proto_stats->sessions_count, proto_stats->sessions_count - proto_stats->timedout_sessions_count,
                //proto_stats->sessions_count, ((int64_t) (proto_stats->sessions_count - proto_stats->timedout_sessions_count) > 0)?proto_stats->sessions_count - proto_stats->timedout_sessions_count:0,
                proto_stats->data_volume, proto_stats->payload_volume, proto_stats->packets_count);
             */
        }
        reset_statistics(proto_stats);
        //if (proto_id==99)reset_eth_statistics(eth_stat);
        proto_stats = proto_stats->next;
    }
}
