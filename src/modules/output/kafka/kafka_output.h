/*
 * kafka_output.h
 *
 *  Created on: May 29, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_OUTPUT_KAFKA_KAFKA_OUTPUT_H_
#define SRC_MODULES_OUTPUT_KAFKA_KAFKA_OUTPUT_H_

#include "../../../configure.h"

typedef struct kafka_output_struct kafka_output_t;

kafka_output_t *kafka_output_init( const kafka_output_conf_t * );
bool kafka_output_send( kafka_output_t *, const char *msg );
void kafka_output_release(  kafka_output_t * );

#endif /* SRC_MODULES_OUTPUT_KAFKA_KAFKA_OUTPUT_H_ */
