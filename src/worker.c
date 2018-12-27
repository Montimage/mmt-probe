/*
 * worker.c
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */


#include <locale.h>
#include "worker.h"

#include "lib/version.h"
#include "lib/string_builder.h"
#include "modules/output/output.h"
#include "modules/output/file/file_output.h"
#include "modules/license/license.h"
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

	ASSERT( ret->dpi_handler != NULL,
		"Cannot initialize MMT-DPI handler: %s", errbuf );

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
		log_write_dual( LOG_INFO, "MMT processed %"PRIu64" packets, dropped %"PRIu64" packets (%.2f%%)"SEC_MSG_FORMAT,
				context->smp[0]->stat.pkt_processed,
				context->smp[0]->stat.pkt_dropped,
				context->smp[0]->stat.pkt_dropped * 100.0 / (context->smp[0]->stat.pkt_processed + context->smp[0]->stat.pkt_dropped)
#ifdef SECURITY_MODULE
				,context->smp[0]->stat.alert_generated
#endif
				);
	}else{
		//get total packets being processed
		for( i = 0; i < context->config->thread->thread_count; i++ )
			pkt_received += context->smp[i]->stat.pkt_processed + context->smp[i]->stat.pkt_dropped;

		//for each thread
		for( i = 0; i < context->config->thread->thread_count; i++ ){
			log_write_dual( LOG_INFO, "Worker %d processed %"PRIu64" packets (%.2f%%), dropped %"PRIu64" packets (%3.2f%%)"SEC_MSG_FORMAT,
					i,
					context->smp[i]->stat.pkt_processed,
					PERCENTAGE( context->smp[i]->stat.pkt_processed,  pkt_received ),
					context->smp[i]->stat.pkt_dropped,
					PERCENTAGE( context->smp[i]->stat.pkt_dropped,  pkt_received )
#ifdef SECURITY_MODULE
				,context->smp[i]->stat.alert_generated
#endif
					);
		}
	}
}

void _send_version_information( output_t *output ){
	struct timeval now;
	gettimeofday (&now, NULL);

#ifdef SECURITY_MODULE
	output_write_report_with_format(
				output,
				CONF_OUTPUT_CHANNEL_ALL, /*sent to all active channels*/
				START_UP_REPORT_TYPE,
				&now,
				"\"%s\",\"%s\",\"%s\"",
				get_version(),
				mmt_version(),
				mmt_sec_get_version_info()
	);
#else
	output_write_report_with_format(
				output,
				CONF_OUTPUT_CHANNEL_ALL, /*sent to all active channels*/
				START_UP_REPORT_TYPE,
				&now,
				"\"%s\",\"%s\"",
				get_version(),
				mmt_version()
	);
#endif
}
/**
 * This callback must be called by a worker thread after starting the thread
 * @param worker_context
 */
void worker_on_start( worker_context_t *worker_context ){
	DEBUG("Starting worker %d", worker_context->index );
	probe_conf_t *config = worker_context->probe_context->config;

	worker_context->output = output_alloc_init( worker_context->index + 1,
			&(config->outputs),
			config->probe_id,
			config->input->input_source,

			//when enable security, we need to synchronize output as it can be called from
			//- worker thread, or,
			//- security threads
#ifdef SECURITY_MODULE
			(config->reports.security->is_enable
			&& config->reports.security->threads_size != 0)
#else
			false
#endif

	);

	worker_context->dpi_context = dpi_alloc_init( config,
			worker_context->dpi_handler, worker_context->output, worker_context->index );

#ifdef SECURITY_MODULE
	worker_context->security = security_worker_alloc_init(
		config->reports.security,
		worker_context->dpi_handler,
		NULL, //core_id is NULL to allow OS arbitrarily arranging security threads on logical cores
		(worker_context->index == 0), //verbose for only the first worker
		worker_context->output,
		config->is_enable_tcp_reassembly
		);
#endif

#ifdef LICENSE_CHECK
	if( worker_context->index == 0 )
		if( !license_check_expiry( get_context()->config->license_file, worker_context->output ))
			ABORT("Licence is either expired or incorrect");
#endif

	//this is performed only by the first worker to inform the beginning of Probe
	if( worker_context->index == 0 )
		_send_version_information( worker_context->output );

//#ifdef DYNAMIC_CONFIG_MODULE
//	if( IS_SMP_MODE( worker_context->probe_context ))
//		if( ->dynamic_conf->is_enable ){
//			dynamic_conf_agency_start();
//		}
//#endif
}

/**
 * This callback must be called by a worker thread before stopping it
 * @param worker_context
 */
void worker_on_stop( worker_context_t *worker_context ){
	DEBUG("Exited worker %d", worker_context->index );

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
//	if( ->dynamic_conf->is_enable ){
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

	CALL_DYNAMIC_CONF_CHECK_IF_NEED( worker_context );

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
	output_flush( worker_context->output );

	//when user enables output for behaviour analysis:
	IF_ENABLE_STAT_REPORT(
		if( worker_context->dpi_context->behaviour_output != NULL )
			file_output_flush( worker_context->dpi_context->behaviour_output );
	);
}
