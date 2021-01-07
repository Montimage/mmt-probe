/*
 * forward_packet.h
 *
 *  Created on: Jan 7, 2021
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_FORWARD_FORWARD_PACKET_H_
#define SRC_MODULES_DPI_FORWARD_FORWARD_PACKET_H_

#include <mmt_core.h>
#include "../../../configure.h"

typedef struct forward_packet_context_struct forward_packet_context_t;

/**
 * Called only once to initial variables
 * @param worker_index
 * @param config
 * @param dpi_handler
 * @return
 */
forward_packet_context_t* forward_packet_start( uint16_t worker_index, const probe_conf_t *config, mmt_handler_t *dpi_handler );

/**
 * Called only once to free variables
 * @param context
 */
void forward_packet_stop( forward_packet_context_t *context );

/**
 * This function must be called on each coming packet
 */
int forward_packet_callback_on_receiving_packet(const ipacket_t * ipacket, forward_packet_context_t *context);



#endif /* SRC_MODULES_DPI_FORWARD_FORWARD_PACKET_H_ */
