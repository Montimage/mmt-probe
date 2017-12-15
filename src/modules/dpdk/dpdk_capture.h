/*
 * dpdk_capture.h
 *
 *  Created on: Dec 14, 2017
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPDK_DPDK_CAPTURE_H_
#define SRC_MODULES_DPDK_DPDK_CAPTURE_H_

#include "../../lib/context.h"

void dpdk_capture_start( probe_context_t *context );
void dpdk_capture_close( probe_context_t *context );

#endif /* SRC_MODULES_DPDK_DPDK_CAPTURE_H_ */
