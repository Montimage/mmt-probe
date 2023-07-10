/*
 * context.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
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

#include "configure.h"
#include "lib/string_builder.h"

#include "modules/output/output.h"

//for each thread
typedef struct worker_context_struct worker_context_t;

typedef struct{
	uint64_t receive;
	uint64_t drop;
}stat_num_t;


//the overall program
typedef struct probe_context_struct{
	probe_conf_t *config;
	pid_t pid;

	//array of thread workers
	worker_context_t **smp;

	//when mmt-probe is exiting
	volatile sig_atomic_t is_exiting;

	//global statistic of network traffic
	struct{
		//number of packets received and dropped by NIC
		stat_num_t nic;

		//data received and dropped by MMT
		struct{
			stat_num_t packets;
			stat_num_t bytes;
		}mmt;
	}traffic_stat;

	//an output for statistics (network traffic, system info) of mmt-probe
	//this output supports multi-threading
	output_t *output;

	struct{
#ifdef PCAP_MODULE
		struct pcap_probe_context_struct *pcap;
#endif
	}modules;
}probe_context_t;


/**
 * Write global statistic of network traffic
 * @param context
 */
static inline void context_print_traffic_stat( const probe_context_t *context, const struct timeval *now ){
	//print a dummy message to inform that MMT-Probe is still alive
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int valid = 0;

	//build message
	STRING_BUILDER_WITH_SEPARATOR(valid, message, sizeof( message ), ",",
			__INT( context->traffic_stat.nic.receive ),
			__INT( context->traffic_stat.nic.drop ),
			__INT( context->traffic_stat.mmt.packets.receive ),
			__INT( context->traffic_stat.mmt.packets.drop ),
			__INT( context->traffic_stat.mmt.bytes.receive ),
			__INT( context->traffic_stat.mmt.bytes.drop )
			);

	if( context->config->reports.cpu_mem->is_enable ){
		//output to all channels
		output_write_report(context->output, context->config->reports.cpu_mem->output_channels, DUMMY_REPORT_TYPE,
			now, message );

		//flush immediately ???
		output_flush( context->output );
	}


	log_write_dual( LOG_INFO, "%s%% dropped by NIC %.4f, by MMT %.4f", message,
			context->traffic_stat.nic.receive == 0? 0 :
					(context->traffic_stat.nic.drop * 100.0 / context->traffic_stat.nic.receive ),
			context->traffic_stat.nic.receive == 0? 0 :
					(context->traffic_stat.mmt.packets.drop * 100.0 / context->traffic_stat.nic.receive )
	 );
}

/**
 * Get the global context of MMT-Probe.
 * The function is implemented by main.c
 * @return
 */
probe_context_t *get_context();

/**
 * Determine when MMT-Probe is running in multi threads or single thread
 */
#define IS_SMP_MODE( context ) (context->config->thread->thread_count != 0)



#endif /* SRC_LIB_CONTEXT_H_ */
