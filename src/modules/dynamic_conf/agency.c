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

static void _process_param( int ident, size_t data_len, const char *data ){
	//update the config in the main process.
	//this update will be transfered to its children once they are created (by using fork)
	//conf_override_element_by_id( get_context()->config, ident, data );
}

static int _receive_message( const char *message, size_t message_size, void *user_data ){
	const command_t *cmd = (command_t *) message;
	DEBUG( "Received command id %d", cmd->id );

	switch( cmd->id ){
	case DYN_CONF_CMD_UPDATE:
		parse_update_parameters( cmd->parameter, cmd->parameter_length, _process_param );
		return DYN_CONF_CMD_REPLY_OK;
		break;
	}
	return DYN_CONF_CMD_REPLY_DO_NOTHING;
}

bool dynamic_conf_agency_start(){
	if( mmt_bus_subscribe( _receive_message, NULL ) == false){
		log_write( LOG_ERR, "Cannot subscribe to mmt-bus");
		return false;
	}
	return true;
}
