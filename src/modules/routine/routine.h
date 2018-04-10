/*
 * routine.h
 *
 *  Created on: Dec 22, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_ROUTINE_ROUTINE_H_
#define SRC_MODULES_ROUTINE_ROUTINE_H_

#include "../../context.h"

typedef struct routine_struct routine_t;

routine_t *routine_create_and_start( probe_context_t * );

void routine_stop_and_release( routine_t *);

#endif /* SRC_MODULES_ROUTINE_ROUTINE_H_ */
