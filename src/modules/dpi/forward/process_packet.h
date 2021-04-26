/*
 * process_packet.h
 *
 *  Created on: Jan 8, 2021
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_FORWARD_PROCESS_PACKET_H_
#define SRC_MODULES_DPI_FORWARD_PROCESS_PACKET_H_

#include <mmt_core.h>
#include <mmt_security.h>
#include <tcpip/mmt_tcpip.h>
#include <mobile/mmt_mobile.h>

typedef enum {
	ACTION_FORWARD,
	ACTION_DROP
}forward_action_t;

void set_forward_action(forward_action_t);
void set_attribute_number_value(uint32_t, uint32_t, uint64_t);

uint64_t get_number_value(uint32_t proto_id, uint32_t att_id, const mmt_array_t *const trace);

#endif /* SRC_MODULES_DPI_FORWARD_PROCESS_PACKET_H_ */
