/*
 * worker.h
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_LIB_WORKER_H_
#define SRC_LIB_WORKER_H_



#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include <signal.h>
#include <mmt_core.h>

#include "context.h"
#include "configure.h"

#include "lib/limit.h"
#include "lib/malloc.h"
#include "lib/memory.h"
#include "lib/system_info.h"
#include "lib/ms_timer.h"


#include "modules/output/output.h"
#include "modules/dpi/dpi.h"
#include "modules/lpi/lpi.h"

struct security_context_struct;

//for each thread
struct worker_context_struct{
	mmt_handler_t *dpi_handler;
	//statistics
	struct {
		uint64_t pkt_processed; //number of packets being processed by worker
		uint64_t pkt_dropped;   //number of packets be dropped by worker
		uint64_t last_pkt_processed; //number of packets being processed by worker at the last stat moment
		uint64_t last_pkt_dropped;   //these numbers are used to print number of packets being dropped/processed during a stat period
		IF_ENABLE_SECURITY(
				uint64_t alert_generated; //number of alerts being generated by security
		)
	}stat;

	//point to its root
	probe_context_t *probe_context;

	output_t *output;

	dpi_context_t *dpi_context;

	//input capturing, either PCAP or DPDK capture is used but not both of them
	//This checking is done in main.c when compiling
	IF_ENABLE_PCAP(
			struct pcap_worker_context_struct *pcap );

	IF_ENABLE_DPDK(
			struct dpdk_worker_context_struct *dpdk );


	IF_ENABLE_SECURITY(
			struct security_context_struct *security);

	//light-packet-inspection: contrary to DPI, we do LPI to get few stats of packets which are in DDoS attack
	// LPI processes quickly packets to avoid consuming resources
	// ==> MMT-Probe can live in DDoS attacks which usually cause DPI to consume a lot of resources and then to generate a lot of reports
	lpi_t *lpi;

	uint16_t index;    //thread index
	uint16_t lcore_id; //id of logical core on which the thread is running
	pid_t    pid;

	//this timer is fired to flush reports to output channels, such as, file, socket, etc
	ms_timer_t flush_report_timer;
};

/**
 * Main processing of a worker.
 * This function simply transfers packets to MMT-DPI to classify.
 * Once the packet being classified, MMT-DPI will trigger our callbacks to do reports, reconstruction, ...
 * @param worker_context
 * @param pkt_header
 * @param pkt_data
 */
void worker_process_a_packet( worker_context_t *worker_context, struct pkthdr *pkt_header, const u_char *pkt_data );

worker_context_t * worker_alloc_init(uint32_t stack_type);

void worker_release( worker_context_t *worker_context );

/**
 * This callback is called after starting a worker
 * @param worker_context
 */
void worker_on_start( worker_context_t *worker_context );

/**
 * This callback is called before stopping a worker
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context );

/**
 * Update timer in the worker
 * @param worker_context
 * @param tv
 */
void worker_update_timer( worker_context_t *worker_context, const struct timeval *tv );

/**
 * Print common statistics for both DPDK and pcap captures, such as, number of packets being captured,
 * @param context
 */
void worker_print_common_statistics( const probe_context_t *context );

#endif /* SRC_LIB_WORKER_H_ */
