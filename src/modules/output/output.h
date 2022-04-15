/*
 * output.h
 *
 *  Created on: Dec 18, 2017
 *          by: Huu Nghia
 *
 * This can be seen as an abstract output channel (an interface) or a dispatcher that dispatches reports to the output channels.
 * MMT-Probe does not work directly with output channels. It works only with this.
 */

#ifndef SRC_MODULES_OUTPUT_OUTPUT_H_
#define SRC_MODULES_OUTPUT_OUTPUT_H_

#include "../../configure.h"

typedef struct output_struct output_t;

/*
 * IDs of report types
 */
typedef enum{
	START_UP_REPORT_TYPE          =    1, /**< Send only once when starting probe */
	MICRO_FLOW_REPORT_TYPE        =    8,//!< MICRO_FLOW_REPORT_TYPE
	RADIUS_REPORT_TYPE            =    9,//!< RADIUS_REPORT_TYPE
	SECURITY_REPORT_TYPE          =   10,//!< SECURITY_REPORT_TYPE
	LICENSE_REPORT_TYPE           =   30,//!< LICENSE_REPORT_TYPE
	NON_SESSION_REPORT_TYPE       =   99,//!< NON_SESSION_REPORT_TYPE
	SESSION_REPORT_TYPE           =  100,//!< SESSION_REPORT_TYPE
	IP_FRAG_REPORT_TYPE           =  101,//!< IP_FRAG_REPORT_TYPE
	DUMMY_REPORT_TYPE             =  200,//!< DUMMY_REPORT_TYPE
	SYSTEM_REPORT_TYPE            =  201,//!< SYSTEM_REPORT_TYPE
	HTTP_RECONSTRUCT_REPORT_TYPE  =  301,//!< HTTP_RECONSTRUCT_REPORT_TYPE
	FTP_RECONSTRUCT_REPORT_TYPE   =  302,//!< FTP_RECONSTRUCT_REPORT_TYPE
	LTE_TOPOLOGY_REPORT_TYPE      =  400,
	LTE_QOS_REPORT_TYPE           =  401,
	EVENT_REPORT_TYPE             = 1000,//!< EVENT_REPORT_TYPE
	QUERY_REPORT_TYPE             =  999,//!< QUERY_REPORT_TYPE
}report_type_t;

/**
 * One output for one worker.
 * @param output_id        : ID of output. Two output instances must have 2 distinguished ID.
 * @param config           : configuration of output
 * @param probe_id         : ID of MMT-Probe. This is used to print out the common part of reports.
 * @param input_src        : Input source. This is used to print out the common part of reports.
 * @param is_multi_threads : indicates whether the result output instance will be used by multi threads
 *                            (for example by multi threads of security).
 *                            If yes, a mutex will be introduced to synchronize their function calls.
 * @return
 *  - NULL if the output is disable
 *  - an instance of output
 */
output_t *output_alloc_init( uint16_t output_id, const struct output_conf_struct *config, uint32_t probe_id, const char* input_src, bool is_multi_threads  );

/**
 * Write an entire report to output channels.
 * @param output
 * @param channels
 * @param message
 * @return
 */
int output_write( output_t *output, output_channel_conf_t channels, const char *report );

/**
 * Write a message to output channels.
 * @param output
 * @param channels    : the set of channels to be writing on, CONF_OUTPUT_CHANNEL_ALL if write to all available channels
 * @param report_type : type of report
 * @param ts          : timestamp to write in the common part of the report
 * @param message_body: main body of the report
 * @return number of channels being received the output message
 */
int output_write_report( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* message_body);

/**
 * Write a message to output channels.
 * This function is same as @output_write_report, however it is slower
 * as it needs to build report body from input parameters.
 * @param output
 * @param channels
 * @param report_type
 * @param ts
 * @param format
 * @return
 */
int output_write_report_with_format( output_t *output, output_channel_conf_t channels,
		report_type_t report_type, const struct timeval *ts,
		const char* format, ...)
__attribute__((format (printf, 5, 6)));

/**
 * Flush the current cache of output to its destination.
 * Depending on the kind of output channel, its implementations may be different.
 * For example, in case of output to file, this will trigger flush current file cache to a file
 * 	(and create a new sample output file if file-output.sample-file=true)
 * In case of output to mongodb, this will trigger an insertion of all documents in mongodb cache to database.
 * @param output
 */
void output_flush( output_t *output );

/**
 * Close its channels and release the resources.
 * @param
 */
void output_release( output_t * );

#endif /* SRC_MODULES_OUTPUT_OUTPUT_H_ */
