/*
 * pcap_dump.h
 *
 *  Created on: Apr 18, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_PCAP_DUMP_PCAP_DUMP_H_
#define SRC_MODULES_DPI_PCAP_DUMP_PCAP_DUMP_H_

#include "../dpi.h"

typedef struct pcap_dump_context_struct pcap_dump_context_t;

pcap_dump_context_t* pcap_dump_start( uint16_t worker_index, const probe_conf_t *config, mmt_handler_t *dpi_handler );

/**
 * This function must be called on each coming packet
 */
int pcap_dump_callback_on_receiving_packet(const ipacket_t * ipacket, pcap_dump_context_t *context);

void pcap_dump_stop( pcap_dump_context_t *context );


#endif /* SRC_MODULES_DPI_PCAP_DUMP_PCAP_DUMP_H_ */
