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
#include "../../configure_override.h"

static int _receive_message( const char *message, size_t message_size, void *user_data ){
	const command_t *cmd = (command_t *) message;
	size_t size = conf_get_identities( NULL );
	command_param_t params[ size ];

	DEBUG( "Received command id %d", cmd->id );

	switch( cmd->id ){
	case DYN_CONF_CMD_UPDATE:
		parse_command_parameters( cmd->parameter, cmd->parameter_length, params, size );
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

void dynamic_conf_agency_stop(){
	mmt_bus_unsubscribe();
}


/**
 * In this function we decide which parameters can be updated with/without restarting MMT-Probe
 * @param ident represents the paramter identity
 * @return true if we need to restart the main processing process to be able to update the parameter
 *         false, otherwise
 */
bool dynamic_conf_need_to_restart_to_update( int ident ){
	switch( ident ){
	case CONF_ATT__NONE:
		return false;
//currently suppose that other parameters are need to restart to be able to update
	default:
		return true;
	}
	return false;
}
