/*
 * server.h
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 *
 *  This is a server. It listens on local network using UNIX domain socket.
 *  It receives commands to dynamically reconfigure MMT-Probe.
 *  Once received a command, it will do:
 *  - check if the command is well-formatted
 *  - if ok, it forwards the commands to the main process
 *      + waiting for a response, then replies to the sender
 *  - if not, replies an error code to the sender
 *
 *  The communications between the server process and the main process are done via mmt_bus
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_SERVER_H_
#define SRC_MODULES_DYNAMIC_CONF_SERVER_H_

#include <stdbool.h>
#include "command.h"

enum{
	CMD_SUCCESS      = 0,
	CMD_SYNTAX_ERROR = 1,
	CMD_OVER_SIZE    = 2,
};

/**
 * Get a list of command_t being stored in buffer.
 * Data in the buffer is constructed by server.c
 * @param buffer
 * @param buffer_size
 * @param lst
 * @param command_size
 * @return
 */
size_t parse_command_parameters( const char *buffer, size_t buffer_size, command_param_t * lst, size_t command_size );

/**
 * Start the server to listen on a file descriptor.
 * It is stopped by SIGINT (Ctrl+C) signal
 * @param unix_domain_descriptor
 * @return
 */
bool dynamic_conf_server_start_processing( const char* unix_domain_descriptor );


#endif /* SRC_MODULES_DYNAMIC_CONF_SERVER_H_ */
