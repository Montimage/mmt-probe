/*
 * dynamic_conf.h
 *
 *  Created on: Dec 26, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_
#define SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_

#include <stdbool.h>
#include "agency.h"


typedef struct dynamic_conf_struct dynamic_config_context_t;

bool dynamic_conf_alloc_and_init( pid_t *processing_pid );

/**
 * Create a new process to listen on a local UNIX socket to receive control commands.
 * @param unix_socket_domain_descriptor_name
 * @param clean_resource callback will be called before exiting the child process
 * @return pid of the child process being created
 */
pid_t dynamcic_conf_create_new_process_to_receive_command( const char * unix_socket_domain_descriptor_name, void (*clean_resource)() );

/**
 * This function must be called periodically by each process to check if there will be new configuration
 */
void dynamic_conf_check();

void dynamic_conf_release();


#endif /* SRC_MODULES_DYNAMIC_CONF_DYNAMIC_CONF_H_ */
