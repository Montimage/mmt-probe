/*
 * routine.c
 *
 *  Created on: Apr 10, 2018
 *          by: Huu Nghia Nguyen
 */

#include "routine.h"
#include "system_stats.h"
#include "../output/output.h"
struct routine_struct{
	system_stats_context_t *system_stats;
	output_t *output;
};



routine_t *routine_create_and_start( probe_context_t * context){
	routine_t *ret = mmt_alloc( sizeof( routine_t ));
	uint16_t output_id = 1;
	if( IS_SMP_MODE( context ) )
		//other outputs of workers have id from 0 -> (context->config->thread->thread_count - 1)
		output_id = context->config->thread->thread_count;

	ret->output  = output_alloc_init( output_id, &context->config->outputs, context->config->probe_id, context->config->input->input_source );
	ret->system_stats = system_stats_alloc_init_start( context->config->reports.cpu_mem, ret->output, context->config->outputs.cache_period );

	return ret;
}

void routine_stop_and_release( routine_t *routine){
	system_stats_release( routine->system_stats );
	output_release( routine->output );
	mmt_probe_free( routine );
}
