/*
 * system_stats.h
 *
 *  Created on: Dec 22, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODUELS_ROUTINE_SYSTEM_STATS_H_
#define SRC_MODUELS_ROUTINE_SYSTEM_STATS_H_

#include "../../configure.h"
#include "../output/output.h"

typedef struct system_stats_context_struct system_stats_context_t;

system_stats_context_t *system_stats_alloc_init_start(  const system_stats_conf_t *config, output_t *output, uint16_t flush_period );

void system_stats_release( system_stats_context_t *);

#endif /* SRC_LIB_SYSTEM_STATS_H_ */
