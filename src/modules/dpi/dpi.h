/*
 * flow_stat.h
 *
 *  Created on: Dec 20, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_STAT_H_
#define SRC_MODULES_DPI_STAT_H_

#include <mmt_core.h>
#include "../../configure.h"
#include "../output/output.h"


typedef struct dpi_context_struct{
	uint16_t worker_index;

	mmt_handler_t *dpi_handler;

	const probe_conf_t *probe_config;

	output_t *output;

	void *event_based_context;

	void *data_dump_context;

	//number of stat_period, e.g., 5s,
	// => this number will increase 1 for each 5 seconds
	size_t stat_periods_index;
}dpi_context_t;

/**
 * This must be called by worker when it is initialize
 * @return
 */
dpi_context_t* dpi_alloc_init( const probe_conf_t *, mmt_handler_t *, output_t *, uint16_t worker_index );

/**
 * This function must be called by worker periodically each x seconds( = config.stat_period )
 * @param
 */
void dpi_callback_on_stat_period( dpi_context_t * );

/**
 * This mest be called by worker when it is released
 */
void dpi_release( dpi_context_t *dpi );


#endif /* SRC_MODULES_DPI_FLOW_STAT_H_ */
