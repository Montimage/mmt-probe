/*
 * context.h
 *
 *  Created on: Dec 13, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_CONTEXT_H_
#define SRC_LIB_CONTEXT_H_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h> //for uint64_t PRIu64
#include <stdbool.h>
#include <signal.h>
#include <mmt_core.h>

#include "alloc.h"
#include "configure.h"

//for each thread
typedef struct single_thread_context_struct{
	uint16_t index;	  //thread index
	uint16_t lcore_id; //id of logical core on which the thread is running
	pid_t    pid;
	mmt_handler_t *dpi_handler;

#ifdef PCAP_MODULE
	struct pcap_single_thread_context_struct *pcap;
#endif

	//statistics
	struct {
		uint64_t pkt_processed; //number of packets being processed by MMT
		uint64_t pkt_dropped;   //number of packets be dropped by MMT
	}stat;

}single_thread_context_t;

typedef struct probe_context_struct{
	probe_conf_t *config;
	pid_t pid;

	//array of
	single_thread_context_t **smp;

	//starting modules
	struct probe_context_modules_struct{
#ifdef DPDK_MODULE

#endif

#ifdef PCAP_MODULE
	struct pcap_context_struct *pcap;
#endif
	}modules;

	volatile sig_atomic_t is_aborting;
}probe_context_t;




static inline single_thread_context_t * alloc_init_single_thread_context_t(){
	char errbuf[1024];

	single_thread_context_t *ret = alloc( sizeof( single_thread_context_t ));
	ret->index = 0;
	ret->dpi_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);

	if( ret->dpi_handler == NULL ){
		log_write( LOG_ERR, "Cannot initialize mmt-dpi handler: %s", errbuf );
		exit( EXIT_FAILURE );
	}

	ret->lcore_id = 0;
	ret->pid      = 0;
	ret->stat.pkt_dropped   = 0;
	ret->stat.pkt_processed = 0;

	return ret;
}


static inline void print_statistics( const probe_context_t *context ){
	int i;
	uint64_t pkt_received = 0;
	//single thread
	if( context->config->thread->thread_count  == 1){
		log_write( LOG_INFO, "MMT processed %12"PRIu64" packets, dropped %12"PRIu64" packets (%3.2f%%) \n",
				context->smp[0]->stat.pkt_processed,
				context->smp[0]->stat.pkt_dropped,
				context->smp[0]->stat.pkt_dropped * 100.0 / context->smp[0]->stat.pkt_processed );
	}else{
		//get total packets being processed
		for( i = 0; i < context->config->thread->thread_count; i++ )
			pkt_received += context->smp[i]->stat.pkt_processed;

		//for each thread
		for( i = 0; i < context->config->thread->thread_count; i++ ){
			log_write( LOG_INFO, "- thread %d processed %12"PRIu64" packets (%3.2f%%), dropped %12"PRIu64" packets (%3.2f%%) \n",
					i,
					context->smp[i]->stat.pkt_processed,
					context->smp[i]->stat.pkt_processed * 100.0 /  pkt_received,
					context->smp[i]->stat.pkt_dropped,
					context->smp[i]->stat.pkt_dropped * 100.0 /  pkt_received );
		}
	}
}
#endif /* SRC_LIB_CONTEXT_H_ */
