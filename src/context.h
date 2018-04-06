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
#include "lib/memory.h"
#include "lib/tools.h"

//for each thread
typedef struct worker_context_struct worker_context_t;

//the overall program
typedef struct probe_context_struct{
	probe_conf_t *config;
	pid_t pid;

	//array of thread workers
	worker_context_t **smp;

	volatile sig_atomic_t is_aborting;

	struct{
#ifdef PCAP_MODULE
		struct pcap_probe_context_struct *pcap;
#endif
	}modules;
}probe_context_t;


#define IS_SMP_MODE( context ) (context->config->thread->thread_count != 0)



#endif /* SRC_LIB_CONTEXT_H_ */
