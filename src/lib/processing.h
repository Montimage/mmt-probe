/*
 * packet_processing.h
 *
 *  Created on: Dec 14, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_PROCESSING_H_
#define SRC_LIB_PROCESSING_H_

#include <mmt_core.h>
#include "context.h"


void packet_processing( single_thread_context_t *context, pkthdr_t *header, const u_char *pkt_data );

#endif /* SRC_LIB_PROCESSING_H_ */
