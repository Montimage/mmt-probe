/*
 * no_session_report.h
 *
 *  Created on: Apr 18, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_REPORT_NO_SESSION_REPORT_H_
#define SRC_MODULES_DPI_REPORT_NO_SESSION_REPORT_H_

#include <mmt_core.h>
#include <stdbool.h>
#include "../../output/output.h"

typedef struct no_session_report_context_struct  no_session_report_context_t;

no_session_report_context_t* no_session_report_alloc_init( mmt_handler_t *dpi_handler, output_t *output,
		bool is_enable_ip_fragementation,  bool is_enable_proto_no_session_stat);

void no_session_report_release( no_session_report_context_t* );
/**
 * Being called periodically by #dpi_callback_on_stat_period
 * @param context
 * @return
 */
void no_session_report( no_session_report_context_t*, uint32_t report_number );

#endif /* SRC_MODULES_DPI_REPORT_NO_SESSION_REPORT_H_ */
