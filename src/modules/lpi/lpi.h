/*
 * lpi.h
 *
 *  Created on: May 5, 2023
 *      Author: nhnghia
 *
 *  This file implements "light packet inspection" - lpi.
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

#ifndef SRC_MODULES_SECURITY_LPI_H_
#define SRC_MODULES_SECURITY_LPI_H_

#include <stdint.h>
#include <stdbool.h>
#include <mmt_core.h>
#include "../output/output.h"

typedef struct lpi_struct lpi_t;

/**
 * Initialize the structure
 * @return
 */
lpi_t* lpi_init( output_t *output, output_channel_conf_t output_channels, size_t stat_ms_period, bool multithreading );

/**
 * Relase the structure
 * @param
 */
void lpi_release( lpi_t* );

/**
 * Mark an IP source: LPI will process all packets coming from this IP
 * @param
 * @param ipv4
 */
void lpi_include_ip( lpi_t* , uint32_t ipv4_source );

/**
 * Process an icoming packet
 * @param
 * @param pkt_header
 * @param pkt_data
 * @return
 * - true: if the packet need to be excluded from the DPI engine
 * - false: otherwsie
 */
bool lpi_process_packet( lpi_t*, struct pkthdr *pkt_header, const u_char *pkt_data );

/**
 * Generate reports about the number of packets/data of each IP source
 * @param
 * @param output
 */
void lpi_generate_reports( lpi_t* );

void lpi_update_timer( lpi_t *lpi, const struct timeval * tv);

#endif /* SRC_MODULES_SECURITY_LPI_H_ */
