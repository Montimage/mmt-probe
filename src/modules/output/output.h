/*
 * output.h
 *
 *  Created on: Dec 18, 2017
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_OUTPUT_OUTPUT_H_
#define SRC_MODULES_OUTPUT_OUTPUT_H_

#include "../../lib/configure.h"

typedef struct output_struct output_t;

typedef enum{
	SECURITY_REPORT_TYPE = 10,
	FLOW_REPORT_TYPE     = 100,
	DUMMY_REPORT_TYPE    = 200,
	EVENT_REPORT_TYPE    = 1000,
}report_type_t;

/**
 * One output for one worker
 * @param worker_context
 * @return
 */
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config );

int output_write( output_t *output, const output_channel_conf_t *channels, const char *message );

int output_write_report( output_t *output, const output_channel_conf_t *channels,
		report_type_t report_type, const char* input_src, const struct timeval *ts,
		const char* format, ...)
__attribute__((format (printf, 6, 7)));

void output_flush( output_t *output );

void output_release( output_t * );

#endif /* SRC_MODULES_OUTPUT_OUTPUT_H_ */
