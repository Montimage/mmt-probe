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
#include "../../lib/malloc.h"
#include "../../lib/string_builder.h"


struct system_stats_context_struct{
	const system_stats_conf_t *config;
	uint16_t flush_period;
	output_t *output;
	pthread_t thread_handler;
};

static inline bool _read_cpu_info( unsigned long *cpu_user, unsigned long *cpu_sys, unsigned long *cpu_idle ){
	unsigned long user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
	FILE *fp = fopen("/proc/stat", "r");
	if( fp == NULL ){
		log_write( LOG_ERR, "Cannot open /proc/stat: %s", strerror( errno ) );
		return NULL;
	}
	*cpu_user = *cpu_sys = *cpu_idle = 0;

	if( fp == NULL
			|| fscanf(fp, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
			&user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) != 10){

		log_write( LOG_ERR, "Error in fscanf the cpu stat");
		fclose( fp );
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
		fclose( fp );
		return false;
	}
	fclose( fp );
	return true;
}

typedef struct cpu_struct{
	unsigned long user, system, idle;
}cpu_t;

/* This function monitors CPU and memory usage*/
static void * _stats_routine(void * args){
	system_stats_context_t * context = (system_stats_context_t *)args;

	cpu_t cpu_1;
	cpu_t cpu_2;
	unsigned long diff_cpu_total;
	/* mem_free: The amount of physical RAM, in kilobytes, left unused by the system
	 * mem_avail: An estimate of how much memory is available for starting new applications, without swapping
	 * see https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=34e431b0ae398fc54ea69ff85ec700722c9da773
	 */
	unsigned long mem_avail, mem_total;
	//int freq = *((int*) f);

	struct timeval ts;
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset;

	//disable? no output?
	if( ! context->config->is_enable
		|| IS_DISABLE_OUTPUT( context->config->output_channels ))
		return NULL;

	if( ! _read_cpu_info( &cpu_1.user, &cpu_1.system, &cpu_1.idle)){
		return NULL;
	}

	//allow to cancel this thread (from its parents)
	if( pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL) )
		ABORT("Cannot set PTHREAD_CANCEL_ENABLE");

	uint16_t timer_1 = 0, timer_2 = 0;
	while ( true ) {
		timer_1 ++;
		timer_2 ++;

		//using nanosleep to wake up when having a signal
		//sleep 1 second
		nanosleep( (const struct timespec[]){{ .tv_sec = 1, .tv_nsec = 0}}, NULL );

		//do statistics
		if( timer_1 == 5 ){// context->config->frequency ){
			timer_1 = 0;
			if( ! _read_cpu_info( &cpu_2.user, &cpu_2.system, &cpu_2.idle) ||
						! _read_mem_info( &mem_avail, &mem_total ) ){
				continue;
			}
			//cputime between two sample moments
			diff_cpu_total = (cpu_2.user + cpu_2.system + cpu_2.idle) - (cpu_1.user + cpu_1.system + cpu_1.idle);

			//Print this report every 5 second
			gettimeofday(&ts, NULL);
			output_write_report_with_format(context->output,
					context->config->output_channels,
					SYSTEM_REPORT_TYPE, &ts,
					"%.0f,%.0f,%.0f,%lu,%lu",
					(cpu_2.user - cpu_1.user)     * 100.0 / diff_cpu_total,
					(cpu_2.system - cpu_1.system) * 100.0 / diff_cpu_total,
					(cpu_2.idle - cpu_1.idle)     * 100.0 / diff_cpu_total,
					mem_avail, mem_total );

			//remember last values of cpu
			cpu_1 = cpu_2;
		}

		//flush messages
		if( timer_2 == context->flush_period ){
			timer_2 = 0;
			output_flush( context->output );
		}
	}

	return NULL;
}


system_stats_context_t *system_stats_alloc_init_start( const system_stats_conf_t *config, output_t *output, uint16_t flush_period ){
	if( !config->is_enable )
		return NULL;
	system_stats_context_t *ret = mmt_alloc( sizeof( system_stats_context_t ));
	ret->config  = config;
	ret->output  = output;
	ret->flush_period = flush_period;

	if( pthread_create( &ret->thread_handler, NULL, _stats_routine, ret )){
		log_write( LOG_ERR, "Cannot create thread for system_stats");
		system_stats_release( ret );
		return NULL;
	}

	return ret;
}

void system_stats_release( system_stats_context_t *context){
	if( context == NULL )
		return;

	if( pthread_cancel( context->thread_handler ) )
		log_write(LOG_WARNING, "Cannot stop thread for system_stats");
	//waiting for the thread
	pthread_join( context->thread_handler, NULL );

	mmt_probe_free( context );
}
