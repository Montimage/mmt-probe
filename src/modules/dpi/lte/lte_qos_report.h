/*
 * lte_qos_report.h
 *
 *  Created on: Jun 25, 2019
 *          by: Huu-Nghia
 */

#ifndef SRC_MODULES_DPI_LTE_LTE_QOS_REPORT_H_
#define SRC_MODULES_DPI_LTE_LTE_QOS_REPORT_H_

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <mmt_core.h>
#include "../../output/output.h"

typedef struct lte_qos_report_struct lte_qos_report_t;

lte_qos_report_t *lte_qos_report_register( mmt_handler_t *dpi_handler, bool is_enable, output_channel_conf_t channel, output_t *output);

void lte_qos_report_unregister( lte_qos_report_t *);

#endif /* SRC_MODULES_DPI_LTE_LTE_QOS_REPORT_H_ */
