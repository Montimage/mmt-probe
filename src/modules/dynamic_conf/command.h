/*
 * command.h
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_COMMAND_H_
#define SRC_MODULES_DYNAMIC_CONF_COMMAND_H_

#include <stdint.h>

#define MMT_CMD_PARAM_MAX_LENGTH 10000
enum{
	DYN_CONF_CMD_STOP   = 1,
	DYN_CONF_CMD_START  = 2,
	DYN_CONF_CMD_UPDATE = 3
};

enum{
	DYN_CONF_CMD_REPLY_OK = 0,
	DYN_CONF_CMD_REPLY_CHILD_RUNNING = 1,
	DYN_CONF_CMD_REPLY_CHILD_STOPPING = 1,
	DYN_CONF_CMD_REPLY_DO_NOTHING = 1000
};

typedef struct{
	uint16_t id;
	uint16_t parameter_length;
	char parameter[ MMT_CMD_PARAM_MAX_LENGTH ];
}command_t;

/**
 * Represent a parameter of update command, for example, input.mode=online
 * => ident    = CONF_ATT__INPUT__MODE
 * => data_len = 7 (6bytes for 'online' + 1 bytes for '\0')
 * => data     = "online\0"
 */
typedef struct{
	uint16_t ident;
	uint16_t data_len;
	const char *data ;
}command_param_t;
#endif /* SRC_MODULES_DYNAMIC_CONF_COMMAND_H_ */
