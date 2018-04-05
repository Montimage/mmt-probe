/*
 * system_stats.c
 *
 *  Created on: Dec 21, 2017
 *          by: Huu Nghia
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "system_stats.h"
#include "pthread.h"
#include "../../lib/memory.h"


struct system_stats_context_struct{
	system_stats_conf_t *config;
	uint32_t core_id;
	output_t *output;
	pthread_t thread_handler;
};

static inline bool _read_cpu_info( unsigned long *cpu_user, unsigned long *cpu_sys, unsigned long *cpu_idle ){
	unsigned long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
	FILE *fp = fopen("/proc/stat", "r");

	*cpu_user = *cpu_sys = *cpu_idle = 0;

	if( fp == NULL
			|| fscanf(fp, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			&user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) != 10){

		log_write( LOG_ERR, "Error in fscanf the cpu stat");
		return false;
	}
	fclose(fp);

	*cpu_user = user + nice;
	//cpu used by system (other than by user)
	*cpu_sys  = system + iowait + irq + softirq + steal + guest + guest_nice;
	*cpu_idle = idle;
	return true;
}

static inline bool _read_mem_info( unsigned long *mem_avail, unsigned long *mem_total ){
	/* mem_free: The amount of physical RAM, in kilobytes, left unused by the system
	 * mem_avail: An estimate of how much memory is available for starting new applications, without swapping
	 * see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	 */
	unsigned long mem_free;
	//read memory info
	FILE *fp = fopen("/proc/meminfo", "r");

	if (fp == NULL
			|| fscanf(fp, "%*s %lu %*s %*s %lu %*s %*s %lu %*s", mem_total, &mem_free, mem_avail) != 3){
		log_write( LOG_ERR, "Error in fscanf the mem info");
		return false;
	}
	fclose( fp );
	return true;
}

/* This function monitors CPU and memory usage*/
static void * _stats_routine(void * args){
	probe_context_t * probe_context = (probe_context_t *)args;

	unsigned long cpu_user, cpu_system, cpu_idle;
	unsigned long cpu_user_2, cpu_system_2, cpu_idle_2;
	unsigned long cpu_total;
	/* mem_free: The amount of physical RAM, in kilobytes, left unused by the system
	 * mem_avail: An estimate of how much memory is available for starting new applications, without swapping
	 * see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	 */
	unsigned long mem_avail, mem_total;
	//int freq = *((int*) f);

	struct timeval ts;

	//disable? no output?
	if( ! probe_context->config->reports.cpu_mem->is_enable
		|| ! probe_context->config->reports.cpu_mem->output_channels.is_enable
		|| ! probe_context->config->outputs.is_enable )
		return NULL;

	if( ! _read_cpu_info( &cpu_user, &cpu_system, &cpu_idle))
		return NULL;


	while ( true ) {
		//using usleep to wake up when having a signal
		usleep( probe_context->config->reports.cpu_mem->frequency * 1000 );

		if( ! _read_cpu_info( &cpu_user_2, &cpu_system_2, &cpu_idle_2) ||
					! _read_mem_info( &mem_avail, &mem_total ) )
				return NULL;

		//cputime between two sample moments
		cpu_total = (cpu_user_2 + cpu_system_2 + cpu_idle_2) - (cpu_user + cpu_system + cpu_idle);

		//Print this report every 5 second

		gettimeofday(&ts, NULL);

	}

	return NULL;
}


system_stats_context_t *system_stats_alloc_init_start( const system_stats_conf_t *config, uint32_t core_id, output_t *output ){
	if( !config->is_enable )
		return NULL;
	system_stats_context_t *ret = alloc( sizeof( system_stats_context_t ));
	ret->config  = config;
	ret->core_id = core_id;
	ret->output  = output;

	if( pthread_create( &ret->thread_handler, NULL, _stats_routine, ret )){
		log_write( LOG_ERR, "Cannot create thread for system_stats");
		system_stats_release( ret );
		return NULL;
	}

	return ret;
}

void system_stats_release( system_stats_context_t *context){
	xfree( context );
}
