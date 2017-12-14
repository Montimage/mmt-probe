/*
 * security.h
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#ifndef SRC_LIB_SECURITY_H_
#define SRC_LIB_SECURITY_H_

#include <mmt_core.h>

#ifdef SECURITY_MODULE
#include <mmt_security.h>

#include "../processing.h"

typedef struct sec_wrapper_struct{
	uint64_t msg_count;

	mmt_sec_handler_t *sec_handler;

	const proto_attribute_t **proto_atts;

	uint32_t proto_atts_count;

        mmt_handler_t * mmt_handler;

	int threads_count;
}sec_wrapper_t;

/**
 * This function init globally mmt-security
 * It must be called from main thread before any register_security
 * @return
 */
int init_security( );

/**
 * This function closes globally mmt-security
 * It must be called from main thread after all unregister_security
 */
void close_security( );

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
sec_wrapper_t* register_security( mmt_handler_t *dpi_handler, size_t threads_count, const uint32_t *cores_id, const char *rules_mask,
		bool verbose, mmt_sec_callback callback, struct smp_thread *th );


/**
 * Stop and free security
 * @param
 * @return number of alerts being generated
 * @note This function must be called from the same thread that calls #register_security
 */
size_t unregister_security( sec_wrapper_t* );


/**
 * Get version information of smp-security
 * @return
 */
static inline const char* security_get_version(){
	return mmt_sec_get_version_info();
}
#endif
#endif /* SRC_LIB_SECURITY_H_ */
