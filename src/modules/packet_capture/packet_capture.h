/*
 * stream_capture.h
 *
 *  Created on: Jun 2, 2021
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_PACKET_CAPTURE_STREAM_STREAM_CAPTURE_H_
#define SRC_MODULES_PACKET_CAPTURE_STREAM_STREAM_CAPTURE_H_

#include "../../context.h"

#ifdef DPDK_CAPTURE_MODULE
#include "dpdk/dpdk_capture.h"
#endif

void packet_capture_start( probe_context_t *context );

void packet_capture_stop( probe_context_t *context );

#endif /* SRC_MODULES_PACKET_CAPTURE_STREAM_STREAM_CAPTURE_H_ */
