/*
 * micro_flow_report.h
 *
 *  Created on: Apr 24, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_REPORT_MICRO_FLOW_REPORT_H_
#define SRC_MODULES_DPI_REPORT_MICRO_FLOW_REPORT_H_

#include <mmt_core.h>
#include <stdbool.h>
#include "../../../configure.h"
#include "../../output/output.h"

typedef struct micro_flow_report_context_struct micro_flow_report_context_t;

/**
 * Create a context that is available during whole execution time of MMT-Probe
 * @param config
 * @param output
 * @return NULL if micro-flow is not enable or no memory
 * 			otherwise, a pointer
 */
micro_flow_report_context_t *micro_flow_report_alloc_init( const micro_flow_conf_t *config, output_t *output  );

/**
 * Check whether a session is a micro flow
 * @param mf
 * @param expired_session
 * @return
 */
bool is_micro_flow( micro_flow_report_context_t *mf, const mmt_session_t * expired_session );

/**
 * Update a micro flow
 * @param mf
 * @param dpi_session
 */
void micro_flow_report__update( micro_flow_report_context_t *mf, const mmt_session_t * dpi_session );

/**
 * Release micro flow report
 * @param
 */
void micro_flow_report_release( micro_flow_report_context_t * );


#endif /* SRC_MODULES_DPI_REPORT_MICRO_FLOW_REPORT_H_ */
