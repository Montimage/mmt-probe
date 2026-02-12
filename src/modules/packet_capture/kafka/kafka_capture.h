/*
 * kafka_capture.h
 *
 *  Created on: Feb 10, 2025
 *      Author: viet
 *
 * Kafka input module for consuming traffic data from Kafka topics.
 * This module follows the same pattern as pcap_capture and dpdk_capture.
 */

#ifndef SRC_MODULES_KAFKA_KAFKA_CAPTURE_H_
#define SRC_MODULES_KAFKA_KAFKA_CAPTURE_H_

#include "../../../context.h"

void kafka_capture_start(probe_context_t *context);

void kafka_capture_stop(probe_context_t *context);

#endif /* SRC_MODULES_KAFKA_KAFKA_CAPTURE_H_ */
