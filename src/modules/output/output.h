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
	SECURITY_REPORT_TYPE    =   10,
	NON_SESSION_REPORT_TYPE =   99,
	SESSION_REPORT_TYPE     =  100,
	SESSION_REPORT_WEB_TYPE =    1, //sub report inside SESSION_REPORT
	SESSION_REPORT_SSL_TYPE =    2, //sub report inside SESSION_REPORT
	SESSION_REPORT_RTP_TYPE =    3, //sub report inside SESSION_REPORT
	SESSION_REPORT_FTP_TYPE =    4, //sub report inside SESSION_REPORT
	IP_FRAG_REPORT_TYPE     =  101,
	DUMMY_REPORT_TYPE       =  200,
	EVENT_REPORT_TYPE       = 1000,
}report_type_t;

/**
 * One output for one worker
 * @param worker_context
 * @return
 */
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src );

int output_write( output_t *output, const output_channel_conf_t *channels, const char *message );

/**
 * Write output to a set of channels: file/redis/kafka
 * @param output
 * @param channels: the set of channels to be writing on, NULL if write to all available channels
 * @param report_type
 * @param input_src
 * @param ts
 * @param format
 * @return number of channels being received the output message
 */
int output_write_report_with_format( output_t *output, const output_channel_conf_t *channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...)
__attribute__((format (printf, 5, 6)));

static inline int output_write_report( output_t *output, const output_channel_conf_t *channels,
		report_type_t report_type, const struct timeval *ts,
		const char* message_body){
	if( message_body == NULL )
		return output_write_report_with_format( output, channels, report_type, ts, NULL );
	else
		return output_write_report_with_format( output, channels, report_type, ts, "%s", message_body );
}

void output_flush( output_t *output );

void output_release( output_t * );

#endif /* SRC_MODULES_OUTPUT_OUTPUT_H_ */
