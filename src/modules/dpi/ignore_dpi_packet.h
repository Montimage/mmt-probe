/*
 * ignore_dpi_packet.h
 *
 *  Created on: May 5, 2023
 *      Author: nhnghia
 *
 *  This file processes packets that must be excluded from the normal processing chain.
 *
 *  Normally a packet goes through the DPI engine to be able to classify and extract its protocols/attributes.
 *  The packet will then goes through the SECURITY engine to be able to verify its attributes against the set of security rules.
 *
 *  When security detected an anomaly, we will not send the packets of the rest of flow to the SECURITY or DPI engine, depending on the parameter "security.ignore-remain-flow".
 *  If the packets are excluded from the DPI engine, then they are also excluded from the SECURITY engine.
 *
 *  Note: currently we exclude all packets coming from an IPv4 source.
 *  TODO: need to support IPv6
 */

#ifndef SRC_MODULES_SECURITY_IGNORE_DPI_PACKET_H_
#define SRC_MODULES_SECURITY_IGNORE_DPI_PACKET_H_

#include <stdint.h>
#include <stdbool.h>
#include <mmt_core.h>
#include "modules/output/output.h"

typedef struct ignore_dpi_packet_struct ignore_dpi_packet_t;

/**
 * Initialize the structure
 * @return
 */
ignore_dpi_packet_t* ignore_dpi_packet_init(  );

/**
 * Relase the structure
 * @param
 */
void ignore_dpi_packet_release( ignore_dpi_packet_t* );

/**
 * Set exclude all traffic from an IP source
 * @param
 * @param ipv4
 */
void ignore_dpi_packet_exclude_ip( ignore_dpi_packet_t* , uint32_t ipv4_source );

/**
 * Process an icoming packet
 * @param
 * @param pkt_header
 * @param pkt_data
 * @return
 * - true: if the packet need to be excluded from the DPI engine
 * - false: otherwsie
 */
bool ignore_dpi_packet_process_packet( ignore_dpi_packet_t*, struct pkthdr *pkt_header, const u_char *pkt_data );

/**
 * Generate reports about the number of packets/data of each IP source
 * @param
 * @param output
 */
void ignore_dpi_packet_generate_reports( ignore_dpi_packet_t*, output_t *output );

#endif /* SRC_MODULES_SECURITY_IGNORE_DPI_PACKET_H_ */
