/*
 * worker.h
 *
 *  Created on: Dec 18, 2017
 *      Author: nhnghia
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
#include "alloc.h"
#include "configure.h"


typedef struct output_struct output_t;

//for each thread
struct worker_context_struct{
	uint16_t       index;    //thread index
	uint16_t       lcore_id; //id of logical core on which the thread is running
	pid_t          pid;
	mmt_handler_t *dpi_handler;
	//statistics
	struct {
		uint64_t pkt_processed; //number of packets being processed by MMT
		uint64_t pkt_dropped;   //number of packets be dropped by MMT
	}stat;

	//point to its root
	probe_context_t *probe_context;

	output_t *output;

#ifdef PCAP_MODULE
	struct pcap_worker_context_struct *pcap;
#else
#ifdef DPDK_MODULE
	struct dpdk_worker_context_struct *dpdk;
#endif
#endif
};

void worker_process_a_packet( worker_context_t *context, pkthdr_t *header, const u_char *pkt_data );


worker_context_t * worker_alloc_init();

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


void worker_print_common_statistics( const probe_context_t *context );

#endif /* SRC_LIB_WORKER_H_ */
