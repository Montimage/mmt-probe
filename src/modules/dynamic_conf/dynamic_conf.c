/*
 * dynamic_conf.c
 *
 *  Created on: Dec 27, 2017
 *          by: Huu Nghia
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "dynamic_conf.h"
#include "../../configure.h"
#include "../../lib/linked_list.h"
#include "../../lib/memory.h"

#include "mmt_bus.h"
#include "server.h"

static int _receive_message( const char *message, size_t message_size, void *user_data ){
	const command_t *cmd = (command_t *) message;
	pid_t *pid = (pid_t *) user_data;

	ASSERT( pid != NULL, "Must not be NULL" );

	switch( cmd->id ){
	case DYN_CONF_CMD_START:
		//it is running
		if( *pid > 0  ){
			return DYN_CONF_CMD_REPLY_CHILD_RUNNING;
		}else{
			*pid = 0; //once the value is changed to 0, the main process will (re)create the processing process
			return DYN_CONF_CMD_REPLY_OK;
		}

		break;
	case DYN_CONF_CMD_STOP:
		if( *pid <= 0 )
			return DYN_CONF_CMD_REPLY_CHILD_STOPPING;
		else{
			//send a Ctrl+C signal to the processing process
			kill( *pid, SIGINT );
			return DYN_CONF_CMD_REPLY_OK;
		}
		break;
//		break;
//	case DYN_CONF_CMD_UPDATE:
//		break;
//	default:
//		log_write( LOG_ERR, "Command is not supported: %d", cmd->id );
	}
	return DYN_CONF_CMD_DO_NOTHING;
}

bool dynamic_conf_alloc_and_init( pid_t *processing_pid ){
	bool ret = mmt_bus_create();
	mmt_bus_subscribe( _receive_message, processing_pid );
	return ret;
}

void dynamic_conf_release(){
	mmt_bus_release();
}


pid_t dynamcic_conf_create_new_process_to_receive_command( const char * unix_socket_domain_descriptor_name, void (*clean_resource)() ){
	//duplicate the current process into 2 different processes
	pid_t child_pid = fork();

	if( child_pid < 0 ) {
		ABORT( "Fork error: %s", strerror(errno) );
		return EXIT_FAILURE;
	}

	if (child_pid == 0) {
		//we are in child process
		log_write( LOG_INFO, "Create a new sub-process %d for dynamic configuration server", getpid() );
		dynamic_conf_server_start_processing( unix_socket_domain_descriptor_name );

		//clean resource
		clean_resource();
		return EXIT_SUCCESS;
	}

	//in parent process
	return child_pid;
}
