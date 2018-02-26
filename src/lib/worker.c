/*
 * worker.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */


#include <mmt_core.h>
#include <locale.h>
#include "worker.h"

#ifdef SECURITY_MODULE
	#include "../modules/security/security.h"
#endif


/**
 * This function must be called by the main thread when allocating a worker
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
	ret->security = NULL;
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
				,context->smp[0]->stat.alert_generated
#endif
					);
		}
	}
}

#ifdef SECURITY_MODULE
/**
 * A function to be called when a rule is validated
 * Note: this function can be called from one or many different threads,
 *       ==> be carefully when using static or global variables inside it
 */
static void _print_security_verdict(
		const rule_info_t *rule,		    //rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,			    //moment (by order of packet) the rule is validated
		const mmt_array_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in register_security
)
{
	worker_context_t *worker = (worker_context_t *) user_data;
	if( worker->security == NULL )
		return;

	const output_channel_conf_t *channels = & worker->security->config->output_channels;
	const char *description = rule->description;
	const char *exec_trace  = mmt_convert_execution_trace_to_json_string( trace, rule );


	struct timeval ts;
	mmt_sec_decode_timeval(timestamp, &ts );

	output_write_report_with_format( worker->output,
			channels,
			SECURITY_REPORT_TYPE,
			&ts,
			"%"PRIu32",\"%s\",\"%s\",\"%s\",%s",
			rule->id,
			verdict_type_string[verdict],
			rule->type_string,
			description,
			exec_trace
			);
}
#endif


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

	IF_ENABLE_SECURITY_MODULE(
	worker_context->security = security_worker_alloc_init( worker_context->probe_context->config->reports.security,
				worker_context->dpi_handler, cores_id,
				(worker_context->index == 0), //verbose for only the first worker
				_print_security_verdict, worker_context));
}

/**
 * This callback must be called by a worker thread before stopping it
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context ){
	IF_ENABLE_SECURITY_MODULE(
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
		output_write_report_with_format(worker_context->output, NULL, DUMMY_REPORT_TYPE,
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
