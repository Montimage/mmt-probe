/*
 * server.c
 *
 *  Created on: May 16, 2018
 *          by: Huu Nghia Nguyen
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <string.h>
#include <errno.h>

#include "server.h"
#include "mmt_bus.h"
#include "command.h"

#include "../../lib/log.h"
#include "../../lib/tools.h"
#include "../../lib/limit.h"

//we allocate buffer to be able to stock at least one command
#define BUFFER_SIZE MMT_CMD_PARAM_MAX_LENGTH

#define IS_CMD( buf, cmd ) (0 == strncmp( buf, cmd, sizeof( cmd ) - 1 ))
#define REPLY( code, sock, txt )         \
do{                                      \
	write( sock, txt, sizeof( txt ) -1 );\
	log_write( code, txt );              \
}while( 0 )

static int socket_fd = 0;
static struct sockaddr_un address;

static inline void _processing( int sock ) {
	int ret;
	char buffer[ BUFFER_SIZE ];
	uint16_t reply_code;
	const char *cmd_str = NULL;
	command_t command;

	do{
		ret = recv( sock, buffer, BUFFER_SIZE, MSG_WAITALL);
		if( ret == 0 ) break;

		if( IS_CMD( buffer, "start" )){
			command.id = DYN_CONF_CMD_START;
			command.parameter_length = 0;
			cmd_str = "start";
		}else if( IS_CMD( buffer, "stop" )){
			command.id = DYN_CONF_CMD_STOP;
			command.parameter_length = 0;
			cmd_str = "stop";
		}else if( IS_CMD( buffer, "update" )){
			cmd_str = "update";
		}else{
			REPLY( LOG_ERR, sock, "syntax_error" );
			continue;
		}

		log_write( LOG_INFO, "Publish command id %d (%s)", command.id, cmd_str );

		//4: 2bytes of id + 2bytes of paramter_length
		ret = mmt_bus_publish( (char *) &command, 4 + command.parameter_length, NULL );

		switch( ret ){
		case MSG_BUS_OLD_MSG_NO_CONSUME:
			REPLY( LOG_ERR, sock, "Old message is not consumed. Need to wait then resend again." );
			break;
		case MMT_BUS_SUCCESS:
			REPLY( LOG_INFO, sock, "Successfully processed the command" );
			break;
		}

	}while( true );

	close( sock );
}

static void _signal_handler( int type ){
	log_write(LOG_INFO, "Received Ctrl+C. Exit dynamic configuration server.");
	close( socket_fd );
	unlink( address.sun_path );
	EXIT_NORMALLY;
}

bool dynamic_conf_server_start_processing( const char* unix_domain_descriptor ){
	int  newsock_fd;
	struct sockaddr_un cli_addr;
	socklen_t sock_len = sizeof( cli_addr );

	//default signal to exit
	signal( SIGINT, _signal_handler );

	//use UNIX socket
	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		ABORT( "Error when opening socket: %s", strerror( errno ) );
		return false;
	}

	memset(&address, 0, sizeof( address ));
	address.sun_family = AF_UNIX;
	strncpy( address.sun_path, unix_domain_descriptor, sizeof( address.sun_path ) );
	unlink( address.sun_path ); //remove the existing file

	if (bind(socket_fd, (struct sockaddr *)&address, strlen(address.sun_path) + sizeof(address.sun_family)) == -1) {
		ABORT("Error when binding dynamic configuration server: %s", strerror( errno ) );
		return false;
	}

	//only one connection at a time
	if (listen(socket_fd, 1) == -1) {
		ABORT("Error when listening dynamic configuration server: %s", strerror( errno ) );
		return false;
	}

	log_write( LOG_INFO, "Dynamic configuration server is listening on %s", unix_domain_descriptor );

	while( true ){
		//Accept actual connection from the client
		newsock_fd = accept(socket_fd, (struct sockaddr *) &cli_addr, &sock_len);
		ASSERT( newsock_fd >= 0, "Error when accepting: %s", strerror( errno ) );

		log_write(LOG_INFO, "Dynamic configuration server received a connection");

		//processing the connection
		//only one client is served at a time
		_processing( newsock_fd );
	}
	return true;
}
