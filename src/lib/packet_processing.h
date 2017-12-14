/*
 * packet_processing.h
 *
 *  Created on: Dec 14, 2017
 *      Author: nhnghia
 */

#ifndef SRC_LIB_PACKET_PROCESSING_H_
#define SRC_LIB_PACKET_PROCESSING_H_

#include "context.h"

void packet_processing( probe_context_t *context, struct pkthdr *header, const u_char *pkt_data );

#endif /* SRC_LIB_PACKET_PROCESSING_H_ */
