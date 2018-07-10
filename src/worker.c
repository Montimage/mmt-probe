/*
 * worker.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */


#include <locale.h>
#include "worker.h"

#include "modules/output/output.h"
#include "lib/license.h"
#include "lib/string_builder.h"
#include "modules/dynamic_conf/dynamic_conf.h"

#ifdef SECURITY_MODULE
#include "modules/security/security.h"
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
		ABORT( "Cannot initialize mmt-dpi handler: %s", errbuf );
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

	dpi_release( worker_context->dpi_context );

	output_release( worker_context->output );

	mmt_probe_free( worker_context );
}

/**
 * This function is called by the main thread before freeing a worker
 * @param context
 */
void worker_print_common_statistics( const probe_context_t *context ){

#ifdef SECURITY_MODULE
#define SEC_MSG_FORMAT ", generated %"PRIu64" alerts"
#else
#define SEC_MSG_FORMAT ""
#endif

	int i;
	uint64_t pkt_received = 0;

	setlocale( LC_NUMERIC, "en_US.UTF-8" );

	//single thread
	if( !IS_SMP_MODE( context )){
		log_write_dual( LOG_INFO, "MMT processed %"PRIu64" packets, dropped %"PRIu64" packets (%.2f%%)"SEC_MSG_FORMAT" \n",
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
			log_write_dual( LOG_INFO, "Worker %d processed %"PRIu64" packets (%.2f%%), dropped %"PRIu64" packets (%3.2f%%)"SEC_MSG_FORMAT" \n",
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
 * This callback must be called by a worker thread after starting the thread
 * @param worker_context
 */
void worker_on_start( worker_context_t *worker_context ){
	DEBUG("Starting worker %d", worker_context->index );

#ifdef TCP_REASSEMBLY_MODULE
	if( worker_context->probe_context->config->is_enable_tcp_reassembly )
		enable_mmt_reassembly( worker_context->dpi_handler );
	else
		disable_mmt_reassembly( worker_context->dpi_handler );
#endif

	worker_context->output = output_alloc_init( worker_context->index,
			&(worker_context->probe_context->config->outputs),
			worker_context->probe_context->config->probe_id,
			worker_context->probe_context->config->input->input_source,

			//when enable security, we need to synchronize output as it can be called from
			//- worker thread, or,
			//- security threads
#ifdef SECURITY_MODULE
			(worker_context->probe_context->config->reports.security->is_enable
			&& worker_context->probe_context->config->reports.security->threads_size != 0)
#else
			false
#endif

	);

	worker_context->dpi_context = dpi_alloc_init( worker_context->probe_context->config,
			worker_context->dpi_handler, worker_context->output, worker_context->index );

#ifdef SECURITY_MODULE
	worker_context->security = security_worker_alloc_init(
		worker_context->probe_context->config->reports.security,
		worker_context->dpi_handler,
		NULL, //core_id is NULL to allow OS arbitrarily arranging security threads on logical cores
		(worker_context->index == 0), //verbose for only the first worker
		worker_context->output );
#endif

#ifdef LICENSE_CHECK
	if( worker_context->index == 0 )
		if( !license_check_expiry( get_context()->config->license_file, worker_context->output ))
			ABORT("Licence is either expired or incorrect");
#endif

//#ifdef DYNAMIC_CONFIG_MODULE
//	if( IS_SMP_MODE( worker_context->probe_context ))
//		if( worker_context->probe_context->config->dynamic_conf->is_enable ){
//			dynamic_conf_agency_start();
//		}
//#endif
}

/**
 * This callback must be called by a worker thread before stopping it
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context ){
	IF_ENABLE_SECURITY(
		worker_context->stat.alert_generated = security_worker_release( worker_context->security );
	)
	dpi_close( worker_context->dpi_context );

//#ifdef DYNAMIC_CONFIG_MODULE
//	dynamic_conf_agency_stop();
//#endif
}


//#ifdef DYNAMIC_CONFIG_MODULE
//static inline void CALL_DYNAMIC_CONF_CHECK_IF_NEED( worker_context_t *worker_context ){
//	if( worker_context->probe_context->config->dynamic_conf->is_enable ){
//		dynamic_conf_check();
//	}
//}
//#else
#define CALL_DYNAMIC_CONF_CHECK_IF_NEED( ... )
//#endif

/**
 * This must be called periodically each x seconds depending on config.stats_period
 * @param worker_context
 */
void worker_on_timer_stat_period( worker_context_t *worker_context ){
	struct timeval now;
	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int valid;

	CALL_DYNAMIC_CONF_CHECK_IF_NEED( worker_context );
	//the first worker
//	if( worker_context->index == 0 ){
//	}

	//print a dummy message to inform that MMT-Probe is still alive
	if( worker_context->probe_context->config->input->input_mode == ONLINE_ANALYSIS ){
		gettimeofday( &now, NULL );
		valid = 0;
		//build message
		STRING_BUILDER_WITH_SEPARATOR(valid, message, sizeof( message ), ",",
				__INT( worker_context->stat.pkt_processed - worker_context->stat.last_pkt_processed ),
				__INT( worker_context->stat.pkt_dropped - worker_context->stat.last_pkt_dropped ));

		//update stat
		worker_context->stat.last_pkt_processed = worker_context->stat.pkt_processed;
		worker_context->stat.last_pkt_dropped   = worker_context->stat.pkt_dropped;

		//output to all channels
		output_write_report(worker_context->output, CONF_OUTPUT_CHANNEL_ALL, DUMMY_REPORT_TYPE,
				&now, message );
	}

	dpi_callback_on_stat_period( worker_context->dpi_context );
	//TODO: testing restart_application only
	//raise(SIGSEGV);
}

/**
 * This must be called periodically each x seconds (= file-output.output-period) if
 * - file output is enable, and,
 * - file output is sampled
 * @param worker_context
 */
void worker_on_timer_sample_file_period( worker_context_t *worker_context ){
	CALL_DYNAMIC_CONF_CHECK_IF_NEED( worker_context );

	//the first worker
//	if( worker_context->index == 0 ){
//	}

	output_flush( worker_context->output );
}
