/*
 * redis.h
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_OUTPUT_REDIS_REDIS_H_
#define SRC_MODULES_OUTPUT_REDIS_REDIS_H_

#include "../../../configure.h"
typedef struct redis_output_struct redis_output_t;

redis_output_t *redis_init( const redis_output_conf_t * );

void redis_release( redis_output_t *);

bool redis_send( redis_output_t *, const char *msg );

#endif /* SRC_MODULES_OUTPUT_REDIS_REDIS_H_ */
