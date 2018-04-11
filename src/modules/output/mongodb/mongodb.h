/*
 * mongodb.h
 *
 *  Created on: Apr 11, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_OUTPUT_MONGODB_MONGODB_H_
#define SRC_MODULES_OUTPUT_MONGODB_MONGODB_H_

#include "../../../configure.h"

typedef struct mongodb_output_struct mongodb_output_t;

mongodb_output_t* mongodb_output_alloc_init( const mongodb_output_conf_t*config,  uint16_t id );

int mongodb_output_write( mongodb_output_t *mongo, const char *message );

void mongodb_output_release( mongodb_output_t *mongo );

#endif /* SRC_MODULES_OUTPUT_MONGODB_MONGODB_H_ */
