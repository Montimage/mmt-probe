/*
 * command.h
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DYNAMIC_CONF_COMMAND_H_
#define SRC_MODULES_DYNAMIC_CONF_COMMAND_H_

#include <stdint.h>
#include "mmt_bus.h"

#define MMT_CMD_PARAM_MAX_LENGTH 1000
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

#endif /* SRC_MODULES_DYNAMIC_CONF_COMMAND_H_ */
