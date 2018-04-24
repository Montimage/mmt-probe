/*
 * micro_flow_report.c
 *
 *  Created on: Apr 24, 2018
 *          by: Huu Nghia Nguyen
 */


#include "micro_flow_report.h"
#include "../../../lib/memory.h"
#include "../dpi_tool.h"

typedef struct micro_flow_stats_struct {
	struct timeval last_time;
	uint32_t application_id;
	uint32_t flows_nb;
	uint32_t dl_pcount;
	uint32_t ul_pcount;
	uint32_t dl_bcount;
	uint32_t ul_bcount;
} micro_flow_stats_t;


struct micro_flow_report_context_struct{
	const micro_flow_conf_t *config;
	output_t *output;
	//each proto/app having a stat
	micro_flow_stats_t stats[ PROTO_MAX_IDENTIFIER ];
};


micro_flow_report_context_t *micro_flow_report_alloc_init( const micro_flow_conf_t *config, output_t *output  ){
	if( config->is_enable == false )
		return false;
	micro_flow_report_context_t *ret = mmt_alloc_and_init_zero( sizeof( micro_flow_report_context_t ));
	ret->config = config;
	ret->output = output;
	return ret;
}

bool is_micro_flow( micro_flow_report_context_t *mf, const mmt_session_t * dpi_session ){
	if( mf->config->byte_threshold >= get_session_byte_count( dpi_session )
			|| mf->config->packet_threshold >= get_session_packet_count( dpi_session )  )
		return true;
	return false;
}


static inline void _print_micro_flow_report( micro_flow_stats_t *stat, output_t *output, output_channel_conf_t channel ){
	//App id, Nb of flows, DL Packet Count, UL Packet Count, DL Byte Count, UL Byte Count
	output_write_report_with_format(output, channel, MICRO_FLOW_REPORT_TYPE, &stat->last_time,
	            "%u,%u,%u,%u,%u,%u",
	            stat->application_id, stat->flows_nb,
				stat->dl_pcount, stat->ul_pcount,
				stat->dl_bcount, stat->ul_bcount);
}

void micro_flow_report__update( micro_flow_report_context_t *mf, const mmt_session_t * dpi_session ){
	uint32_t app_id = dpi_get_proto_id_from_session( dpi_session );
	micro_flow_stats_t *stat = &mf->stats[ app_id ];

	//update statistic
	stat->dl_pcount += get_session_dl_packet_count(dpi_session);
	stat->dl_bcount += get_session_dl_byte_count(dpi_session);
	stat->ul_pcount += get_session_ul_packet_count(dpi_session);
	stat->ul_bcount += get_session_ul_byte_count(dpi_session);
	stat->last_time = get_session_last_activity_time(dpi_session);
	stat->flows_nb  ++;

	//if the statistic is bigger than some limit?
	if( stat->dl_bcount + stat->ul_bcount > mf->config->report_bytes_count
			|| stat->dl_pcount + stat->dl_pcount > mf->config->report_packets_count
			|| stat->flows_nb > mf->config->report_flows_count ){
		//do report
		_print_micro_flow_report(stat, mf->output, mf->config->output_channels );

		//reset its data
		stat->dl_pcount = 0;
		stat->dl_bcount = 0;
		stat->ul_pcount = 0;
		stat->ul_bcount = 0;
		stat->flows_nb  = 0;
	}
}

void micro_flow_report_release( micro_flow_report_context_t * context ){
	if( context == NULL )
		return;

	int i;
	//report the rest
	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		if( context->stats[i].flows_nb > 0 )
			_print_micro_flow_report( &context->stats[i], context->output, context->config->output_channels );
	}
	mmt_probe_free( context );
}
