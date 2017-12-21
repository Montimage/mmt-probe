/*
 * security.h
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_SECURITY_H_
#define SRC_LIB_SECURITY_H_

#include <mmt_security.h>
#include "../../lib/worker.h"

struct security_context_struct{
	worker_context_t *worker_context;

	size_t msg_count;

	mmt_sec_handler_t *sec_handler;

	const proto_attribute_t **proto_atts;

	uint32_t proto_atts_count;

	int threads_count;

};

/**
 * This function init globally mmt-security
 * It must be called from main thread before any register_security
 * @return
 */
int security_open( );

/**
 * This function closes globally mmt-security
 * It must be called from main thread after all unregister_security
 */
void security_close();

/**
 * Send security alerts' information to file or redis depending .conf file
 * @param rule
 * @param verdict
 * @param timestamp
 * @param counter
 * @param trace
 * @param user_data
 */
void security_print_verdict(
		const rule_info_t *rule,		//rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,					//moment (by order of packet) the rule is validated
		const mmt_array_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in register_security
);

/**
 *
 * @param dpi_handler
 * @param thread_size
 * @param cores_mask
 * @param rule_mask
 * @param verbose
 * @param callback
 * @param user_data
 * @return
 */
security_context_t* security_worker_alloc_init( worker_context_t *worker );


/**
 * Stop and free security
 * @param
 * @return number of alerts being generated
 * @note This function must be called from the same thread that calls #register_security
 */
size_t security_worker_release( security_context_t* );

#endif /* SRC_LIB_SECURITY_H_ */
