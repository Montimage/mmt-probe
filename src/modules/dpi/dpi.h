/*
 * flow_stat.h
 *
 *  Created on: Dec 20, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_STAT_H_
#define SRC_MODULES_DPI_STAT_H_

#include <mmt_core.h>
#include "../../lib/limit.h"
#include "../../configure.h"
#include "../output/output.h"

#include "reconstruct/ftp/ftp_reconstruct.h"
#include "reconstruct/http/http_reconstruct.h"

#ifdef STAT_REPORT
#include "report/micro_flow_report.h"
typedef struct no_session_report_context_struct no_session_report_context_t;
typedef struct list_event_based_report_context_struct list_event_based_report_context_t;
typedef struct session_stat_struct session_stat_t;
#include "report/radius_report.h"
#endif

#ifdef PCAP_DUMP_MODULE
#include "pcap_dump/pcap_dump.h"
#endif

#ifdef HTTP_RECONSTRUCT_MODULE
#include "reconstruct/http/http_reconstruct.h"
#endif

#ifdef TCP_REASSEMBLY_MODULE
#include "reassembly/tcp_reassembly.h"
#endif

//the instances of this structure are used on global scope: during running time of MMT-Probe
typedef struct dpi_context_struct{
	uint16_t worker_index;

	mmt_handler_t *dpi_handler;

	const probe_conf_t *probe_config;

	output_t *output;

	IF_ENABLE_PCAP_DUMP( pcap_dump_context_t *pcap_dump );


	IF_ENABLE_STAT_REPORT(
		no_session_report_context_t *no_session_report;
		list_event_based_report_context_t *event_reports;
		micro_flow_report_context_t *micro_reports;
		radius_report_context_t *radius_report;
	)

	struct{
		IF_ENABLE_FTP_RECONSTRUCT( ftp_reconstruct_context_t *ftp; )
		IF_ENABLE_HTTP_RECONSTRUCT( http_reconstruct_t *http; )
	}data_reconstruct;

	IF_ENABLE_TCP_REASSEMBLY( tcp_reassembly_t *tcp_reassembly; )

	//number of stat_period, e.g., 5s,
	// => this number will increase 1 for each 5 seconds
	size_t stat_periods_index;
}dpi_context_t;

//the instances of this structure are used on session scope: during session period
typedef struct packet_session_struct {
	uint64_t session_id;

	//reference to others
	dpi_context_t *context;
	IF_ENABLE_STAT_REPORT( session_stat_t *session_stat ; )
	IF_ENABLE_HTTP_RECONSTRUCT( http_session_t *http_session; )
} packet_session_t;

static inline packet_session_t *dpi_get_packet_session( const ipacket_t *ipacket ){
	return (packet_session_t *) get_user_session_context_from_packet(ipacket);
}

/**
 * This must be called by worker when it is initialize
 * @return
 */
dpi_context_t* dpi_alloc_init( const probe_conf_t *, mmt_handler_t *, output_t *, uint16_t worker_index );

/**
 * This function must be called by worker periodically each x seconds( = config.stat_period )
 * @param
 */
void dpi_callback_on_stat_period( dpi_context_t * );

/**
 * This mest be called by worker when it is released
 */
void dpi_release( dpi_context_t *dpi );

void dpi_close( dpi_context_t *dpi_context );

#endif /* SRC_MODULES_DPI_FLOW_STAT_H_ */
