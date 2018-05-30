/*
 * socket_output.h
 *
 *  Created on: May 30, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_OUTPUT_SOCKET_OUTPUT_H_
#define SRC_MODULES_OUTPUT_SOCKET_OUTPUT_H_

#include "../../../configure.h"

typedef struct socket_output_struct socket_output_t;

socket_output_t* socket_output_init( const socket_output_conf_t *config );

bool socket_output_send( socket_output_t *context, const char *msg );

void socket_output_release( socket_output_t *context );

#endif /* SRC_MODULES_OUTPUT_SOCKET_OUTPUT_H_ */
