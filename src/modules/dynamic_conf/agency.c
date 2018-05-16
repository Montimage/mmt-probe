/*
 * agency.c
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "agency.h"
#include "mmt_bus.h"
#include "command.h"
#include "server.h"

#include "../../context.h"
#include "../../lib/log.h"
#include "../../lib/tools.h"
#include "../../lib/limit.h"

static int _receive_message( const char *message, size_t message_size, void *user_data ){
	const command_t *cmd = (command_t *) message;
	DEBUG( "Received command id %d", cmd->id );

	switch( cmd->id ){
	case DYN_CONF_CMD_UPDATE:
		break;
	}
	return DYN_CONF_CMD_DO_NOTHING;
}

bool dynamic_conf_agency_start(){
	if( mmt_bus_subscribe( _receive_message, NULL ) == false){
		log_write( LOG_ERR, "Cannot subscribe to mmt-bus");
		return false;
	}
	return true;
}
