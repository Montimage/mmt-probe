/*
 * worker.c
 *
 *  Created on: Dec 18, 2017
 *      Author: nhnghia
 */


#include <mmt_core.h>
#include <locale.h>
#include "worker.h"

#include "../modules/output/output.h"
#include "../modules/dpi/dpi.h"

#ifdef SECURITY_MODULE
	#include "../modules/security/security.h"
#endif

void worker_process_a_packet( worker_context_t *worker_context, struct pkthdr *pkt_header, const u_char *pkt_data ){
	//printf("%d %5d %5d\n", worker_context->index, header->caplen, header->len );
	//fflush( stdout );
	packet_process(worker_context->dpi_handler, pkt_header, pkt_data);
	worker_context->stat.pkt_processed ++;
}

/**
 * This function is called by the main thread when allocating a worker
 * @return
 */
worker_context_t * worker_alloc_init(){
	char errbuf[1024];

	worker_context_t *ret = alloc( sizeof( worker_context_t ));
	ret->index = 0;
	ret->dpi_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);

	if( ret->dpi_handler == NULL ){
		log_write( LOG_ERR, "Cannot initialize mmt-dpi handler: %s", errbuf );
		exit( EXIT_FAILURE );
	}

	ret->lcore_id           = 0;
	ret->pid                = 0;
	ret->stat.pkt_dropped   = 0;
	ret->stat.pkt_processed = 0;

	ret->dpi_context = NULL;
	ret->output      = NULL;

#ifdef SECURITY_MODULE
	ret->security    = NULL;
#endif
	return ret;
}

/**
 * This function is called by the main thread to free a worker
 * @param worker_context
 */
void worker_release( worker_context_t *worker_context ){
	//log_debug("Releasing worker %d", worker_context->index );
	mmt_close_handler( worker_context->dpi_handler );
	xfree( worker_context );
}


/**
 * This function is called by the main thread before freeing a worker
 * @param context
 */
void worker_print_common_statistics( const probe_context_t *context ){
	int i;
	uint64_t pkt_received = 0;

	setlocale( LC_NUMERIC, "en_US.UTF-8" );

	//single thread
	if( !IS_SMP_MODE( context )){
		log_write( LOG_INFO, "MMT processed %"PRIu64" packets, dropped %"PRIu64" packets (%.2f%%) \n",
				context->smp[0]->stat.pkt_processed,
				context->smp[0]->stat.pkt_dropped,
				context->smp[0]->stat.pkt_dropped * 100.0 / context->smp[0]->stat.pkt_processed );
	}else{
		//get total packets being processed
		for( i = 0; i < context->config->thread->thread_count; i++ )
			pkt_received += context->smp[i]->stat.pkt_processed;

		//for each thread
		for( i = 0; i < context->config->thread->thread_count; i++ ){
			log_write( LOG_INFO, "Worker %d processed %"PRIu64" packets (%.2f%%), dropped %"PRIu64" packets (%3.2f%%) \n",
					i,
					context->smp[i]->stat.pkt_processed,
					context->smp[i]->stat.pkt_processed * 100.0 /  pkt_received,
					context->smp[i]->stat.pkt_dropped,
					context->smp[i]->stat.pkt_dropped * 100.0 /  pkt_received );
		}
	}
}


/**
 * This callback is called by a worker thread after starting it
 * @param worker_context
 */
void worker_on_start( worker_context_t *worker_context ){
	//set timeouts
	mmt_handler_t *mmt_dpi = worker_context->dpi_handler;
	const probe_conf_t *config= worker_context->probe_context->config;

	set_default_session_timed_out( mmt_dpi, config->session_timeout->default_session_timeout);
	set_long_session_timed_out(    mmt_dpi, config->session_timeout->long_session_timeout);
	set_short_session_timed_out(   mmt_dpi, config->session_timeout->short_session_timeout);
	set_live_session_timed_out(    mmt_dpi, config->session_timeout->live_session_timeout);


	worker_context->output = output_alloc_init( worker_context );

	worker_context->dpi_context = dpi_alloc_init( worker_context );

#ifdef SECURITY_MODULE
	worker_context->security = security_worker_alloc_init( worker_context );
#endif
}

/**
 * This callback is called by a worker thread before stopping it
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context ){
#ifdef SECURITY_MODULE
	security_worker_release( worker_context->security );
#endif
	output_release( worker_context->output );
	dpi_release( worker_context->dpi_context );
}
