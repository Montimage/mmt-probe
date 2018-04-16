/*
 * worker.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */


#include <mmt_core.h>
#include <locale.h>
#include "worker.h"

#include "modules/output/output.h"

#ifdef SECURITY_MODULE
	#include "modules/security/security.h"
#endif

#ifdef LICENSE_CHECK
#include "lib/license.h"
#endif

/**
 * This function must be called by the main thread when allocating a worker
 * @return
 */
worker_context_t * worker_alloc_init(){
	char errbuf[1024];

	worker_context_t *ret = mmt_alloc_and_init_zero( sizeof( worker_context_t ));
	ret->dpi_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);

	if( ret->dpi_handler == NULL ){
		log_write( LOG_ERR, "Cannot initialize mmt-dpi handler: %s", errbuf );
		exit( EXIT_FAILURE );
	}

	return ret;
}

/**
 * This function is called by the main thread to free a worker
 * @param worker_context
 */
void worker_release( worker_context_t *worker_context ){
	//log_debug("Releasing worker %d", worker_context->index );
	mmt_close_handler( worker_context->dpi_handler );
	mmt_probe_free( worker_context );
}

#ifdef SECURITY_MODULE
#define SEC_MSG_FORMAT ", generated %"PRIu64" alerts"
#else
#define SEC_MSG_FORMAT ""
#endif

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
		log_write( LOG_INFO, "MMT processed %"PRIu64" packets, dropped %"PRIu64" packets (%.2f%%)"SEC_MSG_FORMAT" \n",
				context->smp[0]->stat.pkt_processed,
				context->smp[0]->stat.pkt_dropped,
				context->smp[0]->stat.pkt_dropped * 100.0 / context->smp[0]->stat.pkt_processed
#ifdef SECURITY_MODULE
				,context->smp[0]->stat.alert_generated
#endif
				);
	}else{
		//get total packets being processed
		for( i = 0; i < context->config->thread->thread_count; i++ )
			pkt_received += context->smp[i]->stat.pkt_processed;

		//for each thread
		for( i = 0; i < context->config->thread->thread_count; i++ ){
			log_write( LOG_INFO, "Worker %d processed %"PRIu64" packets (%.2f%%), dropped %"PRIu64" packets (%3.2f%%)"SEC_MSG_FORMAT" \n",
					i,
					context->smp[i]->stat.pkt_processed,
					context->smp[i]->stat.pkt_processed * 100.0 /  pkt_received,
					context->smp[i]->stat.pkt_dropped,
					context->smp[i]->stat.pkt_dropped * 100.0 /  pkt_received
#ifdef SECURITY_MODULE
				,context->smp[i]->stat.alert_generated
#endif
					);
		}
	}
}

/**
 * This callback must be called by a worker thread after starting it
 * @param worker_context
 */
void worker_on_start( worker_context_t *worker_context ){

	DEBUG("Starting worker %d", worker_context->index );
	worker_context->output = output_alloc_init( worker_context->index,
			&(worker_context->probe_context->config->outputs),
			worker_context->probe_context->config->probe_id,
			worker_context->probe_context->config->input->input_source );

	worker_context->dpi_context = dpi_alloc_init( worker_context->probe_context->config,
			worker_context->dpi_handler, worker_context->output, worker_context->index );

	uint32_t *cores_id = (uint32_t []){0,1};

	IF_ENABLE_SECURITY(
	worker_context->security = security_worker_alloc_init(
				worker_context->probe_context->config->reports.security,
				worker_context->dpi_handler, cores_id,
				(worker_context->index == 0), //verbose for only the first worker
				worker_context->output ));

#ifdef LICENSE_CHECK
	if( worker_context->index == 0 )
		if( !license_check_expiry( context.config->license_file, worker_context->output ))
			abort();
#endif
}

/**
 * This callback must be called by a worker thread before stopping it
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context ){
	IF_ENABLE_SECURITY(
		worker_context->stat.alert_generated = security_worker_release( worker_context->security );
	)
	dpi_release( worker_context->dpi_context );
	output_release( worker_context->output );
}


/**
 * This must be called periodically each x seconds depending on config.stats_period
 * @param worker_context
 */
void worker_on_timer_stat_period( worker_context_t *worker_context ){
	struct timeval now;
	//the first worker
	if( worker_context->index == 0 ){
	}

	//print a dummy message to inform that MMT-Probe is still alive
	if( worker_context->probe_context->config->input->input_mode == ONLINE_ANALYSIS ){
		gettimeofday( &now, NULL );
		//output to all channels
		output_write_report_with_format(worker_context->output, CONF_OUTPUT_CHANNEL_ALL, DUMMY_REPORT_TYPE,
				&now, NULL );
	}

	dpi_callback_on_stat_period( worker_context->dpi_context );
}

/**
 * This must be called periodically each x seconds (= file-output.output-period) if
 * - file output is enable, and,
 * - file output is sampled
 * @param worker_context
 */
void worker_on_timer_sample_file_period( worker_context_t *worker_context ){

	//the first worker
//	if( worker_context->index == 0 ){
//	}

	output_flush( worker_context->output );
}
