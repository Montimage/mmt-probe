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

/* the functions can be called in embedded_functions of mmt-security in FORWARD rules */
void mmt_probe_do_not_forward_packet();
void mmt_probe_forward_packet();
void mmt_probe_set_attribute_number_value(uint32_t, uint32_t, uint64_t);

#endif /* SRC_MODULES_DPI_FORWARD_PROCESS_PACKET_H_ */
