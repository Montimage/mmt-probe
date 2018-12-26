/*
 * topology_report.h
 *
 *  Created on: Dec 13, 2018
 *          by: Huu-Nghia
 *
 *  Report elements to be added or removed from the current topology of LTG-5G network
 */

#ifndef SRC_MODULES_DPI_LTE_TOPOLOGY_REPORT_H_
#define SRC_MODULES_DPI_LTE_TOPOLOGY_REPORT_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <mmt_core.h>
#include "../../output/output.h"

typedef struct lte_topo_report_struct lte_topo_report_t;

lte_topo_report_t *lte_topo_report_register( mmt_handler_t *dpi_handler, bool is_enable, output_channel_conf_t channel, output_t *output);

void lte_topo_report_unregister( lte_topo_report_t *);

#endif /* SRC_MODULES_DPI_LTE_TOPOLOGY_REPORT_H_ */
