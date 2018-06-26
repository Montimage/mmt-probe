/*
 * output.h
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_OUTPUT_OUTPUT_H_
#define SRC_MODULES_OUTPUT_OUTPUT_H_

#include "../../configure.h"

typedef struct output_struct output_t;

typedef enum{
	MICRO_FLOW_REPORT_TYPE        =    8,
	RADIUS_REPORT_TYPE            =    9,
	SECURITY_REPORT_TYPE          =   10,
	LICENSE_REPORT_TYPE           =   30,
	NON_SESSION_REPORT_TYPE       =   99,
	SESSION_REPORT_TYPE           =  100,
	IP_FRAG_REPORT_TYPE           =  101,
	DUMMY_REPORT_TYPE             =  200,
	SYSTEM_REPORT_TYPE            =  201,
	HTTP_RECONSTRUCT_REPORT_TYPE  =  301,
	FTP_RECONSTRUCT_REPORT_TYPE   =  302,
	EVENT_REPORT_TYPE             = 1000,
}report_type_t;

/**
 * One output for one worker
 * @param worker_context
 * @return
 */
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src );

int output_write( output_t *output, output_channel_conf_t channels, const char *message );

/**
 * Write output to a set of channels: file/redis/kafka
 * @param output
 * @param channels: the set of channels to be writing on, NULL if write to all available channels
 * @param report_type
 * @param input_src
 * @param ts
 * @param message_body
 * @return number of channels being received the output message
 */
int output_write_report( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* message_body);

int output_write_report_with_format( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...)
__attribute__((format (printf, 5, 6)));


void output_flush( output_t *output );

void output_release( output_t * );

#endif /* SRC_MODULES_OUTPUT_OUTPUT_H_ */
