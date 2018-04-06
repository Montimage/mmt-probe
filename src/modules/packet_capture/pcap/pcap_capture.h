/*
 * pcap_capture.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_PCAP_PCAP_CAPTURE_H_
#define SRC_MODULES_PCAP_PCAP_CAPTURE_H_

#include "../../../context.h"

void pcap_capture_start( probe_context_t *context );

void pcap_capture_stop( probe_context_t *context );

void pcap_capture_release( probe_context_t *context );

#endif /* SRC_MODULES_PCAP_PCAP_CAPTURE_H_ */
