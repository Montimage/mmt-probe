/*
 * stream_capture.c
 *
 *  Created on: Jun 2, 2021
 *      Author: nhnghia
 */


#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "../../../lib/ms_timer.h"
#include "../../../worker.h"


#ifndef STREAM_CAPTURE_MODULE
#define STREAM_CAPTURE_MODULE
#endif

#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "../../../worker.h"
#include "stream_capture.h"

//for one thread
struct stream_worker_context_struct{
	pthread_t thread_handler;
};

//for all application
struct stream_probe_context_struct{
	FILE *handler;
};


static inline void _print_traffic_statistics( const ms_timer_t *timer, void *arg ){
	struct timeval tv;
	probe_context_t *context = arg;

	if( context->config->input->input_mode != ONLINE_ANALYSIS )
		return;

	//get statistics from libpcap
	context->traffic_stat.nic.receive = 0;
	context->traffic_stat.nic.drop    = 0;

	gettimeofday( &tv, NULL );
	context_print_traffic_stat( context, &tv );
}

//this function is called only in single-thread mode to process packets
static void _got_a_line(u_char* user, size_t len, const u_char *data){
	probe_context_t *context   = ( probe_context_t *)user;
	const probe_conf_t *config = context->config;

	//static time_t next_stat_ts = 0; //moment we need to do statistic
	//static time_t next_output_ts = 0; //moment we need flush output to channels
	//static time_t now = 0; //current timestamp that is either
	//- real timestamp of system when running online
	//- packet timestamp when running offline

	struct timeval now;

	//when having packet data to process
	if( data != NULL ){
		pkthdr_t pkt_header;
		//convert from pcap's header to mmt packet's header
		//as no timestamp in "packet" => use the current time
		pkt_header.ts.tv_sec = time( NULL );
		pkt_header.ts.tv_usec = 0;
		pkt_header.caplen    = len;
		pkt_header.len       = len;
		pkt_header.user_args = NULL;

		worker_process_a_packet( context->smp[0], &pkt_header, data );

		now = pkt_header.ts;

		context->traffic_stat.mmt.bytes.receive += len;
		context->traffic_stat.mmt.packets.receive ++;
	}

	//we do not use packet timestamp for online analysis as
	// there may be exist some moment having no packets => output will be blocked until a new packet comes
	//get the current timestamp of system
	if( config->input->input_mode == ONLINE_ANALYSIS )
		gettimeofday( &now, NULL );

	//first times: we need to initialize the 2 milestones
	//if( next_output_ts == 0 && now != 0 ){
	//	next_stat_ts = now + config->stat_period;
	//	next_output_ts = now + config->outputs.cache_period;
	//}

	worker_context_t *worker_context = context->smp[0];
	worker_update_timer(worker_context, &now );
	//statistic periodically
// 	if( now > next_stat_ts  ){
// 		next_stat_ts += config->stat_period;
// 		//global statistic
// 		_print_traffic_statistics( context );

// 		//call worker timer only in non-smp mode
// 		if( ! IS_SMP_MODE( context ))
// 			worker_on_timer_stat_period( worker_context );

// 	}

// 	//if we need to sample output file
// 	if( ! IS_SMP_MODE( context )){
// 		if( config->outputs.file->is_sampled && now >  next_output_ts ){
// 			next_output_ts += config->outputs.cache_period;
// 			//call worker
// 			worker_on_timer_sample_file_period( worker_context );
// 		}
// 	}
}

//this function is called by main thread when user press Ctrl+C
void stream_capture_stop( probe_context_t *context ){
	context->is_exiting = true;
}


/**
 * Release pcap context
 * @param context
 */
static inline void _stream_capture_release( probe_context_t *context ){
	int i;
	//close pcap in main thread
	fclose( context->modules.stream->handler );
	context->modules.stream->handler  = NULL;

	//release resources of each worker
	int workers_count;
	if( IS_SMP_MODE( context ) )
		workers_count = context->config->thread->thread_count;
	else
		workers_count = 1;
	for( i=0; i<workers_count; i++ ){
		mmt_probe_free( context->smp[i]->stream );
		worker_release( context->smp[i] );
	}

	mmt_probe_free( context->smp );
	mmt_probe_free( context->modules.stream );
}



//public API
void stream_capture_start( probe_context_t *context ){
	int i, ret;
	FILE *fd_handler;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	ms_timer_t traffic_stat_report_timer;
	struct timeval now_tv;

	int workers_count;
	if( IS_SMP_MODE( context )){
		ABORT("Does not support multi-threading yet. Set .conf file: thread-nb=0");
	}else{
		log_write( LOG_INFO, "Starting PCAP mode to analyze '%s' using the main thread",
				context->config->input->input_source );
		//this worker will run on the main thread
		workers_count = 1;
	}

	//memory for the pcap module
	context->modules.stream = mmt_alloc_and_init_zero( sizeof( struct stream_probe_context_struct ));

	//allocate context for each thread
	context->smp = mmt_alloc_and_init_zero( sizeof( worker_context_t ) * workers_count );

	//allocate and initialize memory for each worker
	for( i=0; i<workers_count; i++ ){
		context->smp[i] = worker_alloc_init( context->config->stack_type );

		context->smp[i]->index = i;

		//keep a reference to its root
		context->smp[i]->probe_context = context;


		//specific for pcap module
		context->smp[i]->stream = mmt_alloc_and_init_zero( sizeof( struct stream_worker_context_struct ));

		//pthread_spin_init( & context->smp[i]->pcap->spin_lock, PTHREAD_PROCESS_PRIVATE);

		//when there is only one worker running on the main thread
		worker_on_start( context->smp[0] );
	}

	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		fd_handler = fopen( context->config->input->input_source, "r" );
		ASSERT( fd_handler != NULL,
				"Couldn't open file %s: %s\n", context->config->input->input_source, strerror(errno) );
	}else{
		ABORT("Doesn't support ONLINE analysis");
	}

	context->modules.stream->handler = fd_handler;

	ms_timer_init( &traffic_stat_report_timer, context->config->stat_period * S2MS,
			_print_traffic_statistics, context );

	while( ! context->is_exiting ){
		read = getdelim( &line, &len, '\n', fd_handler );
		if( read > 0 ){
			//DEBUG("%s",  line);
			_got_a_line( (u_char*) context, len, (u_char *) line );
		} else
			break;

		gettimeofday( &now_tv, NULL );
		ms_timer_set_time(&traffic_stat_report_timer, &now_tv);
	}

	if (line)
		free(line);
	//stop all workers
	//when there is only one worker running on the main thread
	worker_on_stop( context->smp[0] );

	worker_print_common_statistics( context );

	//all workers have been stopped
	_stream_capture_release( context );
}
