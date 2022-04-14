/*
 * inband_telemetry_report.c
 *
 *  Created on: Jan 10, 2022
 *      Author: nhnghia
 */


#include <mmt_core.h>
#include <types_defs.h>

typedef struct int_info_struct{
	// flow info
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t ip_proto; //TCP ou UDP?

	// u64 pkt_cnt;
	// u64 byte_cnt;

	uint32_t switch_id; //ID of the switch (sink node) that generates this report
	uint32_t seq_number;
	uint32_t hw_id;
	uint32_t hop_latency; //total time of hop_latencies
	uint32_t sink_time; //the moment this report was created by a sink node
	uint8_t  report_metadata_bits; //Report Metadata Bits
	uint8_t  num_int_hop;

	//for each INT node
	mmt_u32_array_t sw_ids;
	mmt_u32_array_t in_port_ids;
	mmt_u32_array_t e_port_ids;
	mmt_u32_array_t hop_latencies;
	mmt_u32_array_t queue_ids;
	mmt_u32_array_t queue_occups;
	mmt_u32_array_t ingr_times;
	mmt_u32_array_t egr_times;
	mmt_u32_array_t lv2_in_e_port_ids;
	mmt_u32_array_t tx_utilizes;

	//details of report_metadata_bits
	uint8_t is_in_egress_port_id;
	uint8_t is_hop_latency;
	uint8_t is_queue_id_occup;
	uint8_t is_egress_time;
	uint8_t is_queue_id_drop_reason_padding;
	uint8_t is_tx_utilize;
}int_info_t;
