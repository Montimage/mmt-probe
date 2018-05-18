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
#include <stdarg.h>

#include "server.h"
#include "mmt_bus.h"
#include "command.h"

#include "../../lib/log.h"
#include "../../lib/tools.h"
#include "../../lib/memory.h"
#include "../../lib/limit.h"
#include "../../configure_override.h"

//we allocate buffer to be able to stock at least one command
#define BUFFER_SIZE MMT_CMD_PARAM_MAX_LENGTH
#define LENGTH( string ) (sizeof( string ) - 1 )
#define IS_CMD( buf, cmd ) (0 == strncmp( buf, cmd, sizeof( cmd ) - 1 ))

#define NEW_LINE '\n'

/**
 * Response to control client in form: code description
 * @param sock
 * @param code
 * @param format
 */
__attribute__((format (printf, 3, 4)))
static inline void _reply( int sock, uint16_t code, const char *format, ... ){
	char message[ BUFFER_SIZE ];
	int offset = snprintf( message, BUFFER_SIZE, "%d ", code);
	va_list args;
	va_start( args, format );
	offset += vsnprintf( message + offset, BUFFER_SIZE - offset, format, args);
	va_end( args );

	write( sock, message, offset );
}

size_t parse_update_parameters( const char *buffer, size_t buffer_size, void (*callback)(int ident, size_t data_len, const char *data) ){
	size_t ret = 0, offset = 0;
	uint16_t ident, data_len;
	const char *data;
	while( offset < buffer_size ){
		//1. The first 2bytes is identity
		assign_2bytes( &ident, &buffer[ offset ]);
		offset += 2;
		//2. The next 2bytes is data length
		assign_2bytes( &data_len, &buffer[ offset ]);
		offset += 2;
		//3. data
		data = &buffer[offset];

		//processing this parameter
		callback( ident, data_len, data );

		//jump to the next parameter
		offset += data_len;
		ret ++;
	}
	DEBUG("Got %zu parameters", ret );
	return ret;
}

/**
 * After executing this function, we get the parameters of update command on `parameter` variable.
 * Each parameter is stocked in format:
 * - the first 2bytes represents identity of the parameter (see the list in `conf_print_identities_list`)
 * - the next 2bytes represents length of data value
 * - the next x bytes represents data value. The data value is always ended by '\0'.
 *     For example, x=5 if data value is 'true\0' (4 effective bytes + 1 byte for '\0')
 *
 * Example, given buffer = "{input.mode=online\n}"
 * => parameter = "xxyyonline\0", in which,
 *  - xx is 2 bytes whose value is 10 representing "input.mode"
 *  - yy is 2 bytes whose value is  7 representing 6 bytes of 'online' and 1  byte of '\0'
 * @param buffer
 * @param buffer_len
 * @param parameter
 * @param param_size
 * @param sock
 * @return - 0 if there exist syntax error in one of the parameters
 *         - otherwise, number of bytes being used to stock the parameters
 *
 *
 */
static inline int _parse_update_parameters( char *buffer, size_t buffer_len, char *parameter, size_t param_size, int sock ){
	char *ident_str, *val_str;
	const char *str_ptr;
	const identity_t *ident;
	uint16_t val, val_len;
	int i;

	DEBUG( "Update parameter: %s", buffer );

	//1. must surround by { and }
	if( buffer_len < 2 || buffer[0] != '{' || buffer[ buffer_len - 1 ] != '}' ){
		_reply( sock, CMD_SYNTAX_ERROR, "Parameters of update command must be surrounded by { and }");
		return 0;
	}
	buffer ++; //jump over {
	buffer_len -= 2; //exclude { and }
	buffer[ buffer_len ] = '\0'; //well null-terminated

	//0. no parameter?
	if( buffer_len == 0 ){
		_reply( sock, CMD_SYNTAX_ERROR, "The update command must contain at least one parameter");
		return 0;
	}

	//2. check parameters

	//each parameter must be ended by \n
	if( buffer[ buffer_len - 1 ] != NEW_LINE ){
		_reply( sock, CMD_SYNTAX_ERROR, "The last parameter of update command must ended by \\n" );
		return 0;
	}

	ident_str = buffer;
	val_str   = ident_str;

	size_t offset = 0;
	do{
		//val_str = 'input.mode=online\nabc.xyz=12\n'

		//we need to jump over the first = character
		while( *val_str != NEW_LINE && *val_str != '=' )
			val_str ++;

		//not found = character
		if( *val_str == NEW_LINE ){
			*val_str = '\0'; //terminate ident_str to be able to used in the next _reply
			_reply( sock, CMD_SYNTAX_ERROR, "Parameter and its value (%s) must be separated by '='", ident_str );
			return 0;
		}

		//We have (*val_str == '=')
		*val_str = '\0'; //null-ended for ident_str;
		//jump over '\0' above
		val_str ++;

		//now ident_str is a string with null-terminated.
		// We will check whether it is existing in our list (see the list in `conf_print_identities_list`)
		ident = conf_get_ident_from_string( ident_str );
		//not found or not supported yet
		if( ident == NULL || ident->data_type == NO_SUPPORT ){
			_reply( sock, CMD_SYNTAX_ERROR, "Does not support parameter '%s'", ident_str );
			return 0;
		}

		//count the length of data value
		val_len = 0;
		while( val_str[ val_len ] != NEW_LINE )
			val_len ++;

		//value is empty
		if( val_len == 0 ){
			_reply( sock, CMD_SYNTAX_ERROR, "Expect value for '%s'", ident_str );
			return 0;
		}

		//ended val_str by '\0'
		val_str[ val_len ] = '\0';
		val_len ++; //take into account '\0'

		//check value depending on data type of parameter
		str_ptr = conf_validate_data_value(ident, val_str);
		if( str_ptr != NULL ){
			_reply( sock, CMD_SYNTAX_ERROR, "%s", str_ptr );
			return 0;
		}


		DEBUG("%s=%s", ident_str, val_str );
		//stock into parameter

		//ensure that we have enough place to stock this parameter
		if( offset + 2 + 2 + val_len > param_size ){
			_reply( sock, CMD_SYNTAX_ERROR, "Huge data value for parameters");
			return 0;
		}

		//First 2bytes contains identity of parameter
		val = ident->val;
		assign_2bytes( &parameter[offset], &val );
		offset += 2;
		//next 2bytes contains value length
		assign_2bytes( &parameter[offset], &val_len );
		offset += 2;
		//next x bytes contains value data
		memcpy( &parameter[offset], val_str, val_len );
		offset += val_len;


		//next parameter
		val_str  += val_len; //to the next
		ident_str = val_str;

	}while( *val_str != '\0'); //reach to the end of string

	//3. everything are ok
	return offset;
}

static int socket_fd = 0;
static struct sockaddr_un address;


#define CMD_START_STR   "start"
#define CMD_STOP_STR    "stop"
#define CMD_UPDATE_STR  "update"

static inline void _processing( int sock ) {
	int ret;
	char buffer[ BUFFER_SIZE ];
	uint16_t reply_code;
	const char *cmd_str = NULL;
	command_t command;

	do{
		ret = recv( sock, buffer, BUFFER_SIZE, MSG_WAITALL);
		if( ret == 0 ) break;

		//if buffer is ended by null-terminated
		if( buffer[ret - 1] == '\0' )
			ret --;// ret = strlen( buffer )
		else{
			//buffer is full => reserve the last element to contain '\0'
			if( ret == BUFFER_SIZE )
				ret --;
			buffer[ ret ] = '\0'; //well terminate the string
		}


		if( IS_CMD( buffer, CMD_START_STR )){
			command.id = DYN_CONF_CMD_START;
			command.parameter_length = 0;
			cmd_str = CMD_START_STR;
		}else if( IS_CMD( buffer, CMD_STOP_STR )){
			command.id = DYN_CONF_CMD_STOP;
			command.parameter_length = 0;
			cmd_str = CMD_STOP_STR;
		}else if( IS_CMD( buffer, CMD_UPDATE_STR )){
			ret = _parse_update_parameters( buffer + LENGTH( CMD_UPDATE_STR ), ret - LENGTH( CMD_UPDATE_STR ), command.parameter, sizeof(command.parameter), sock );
			//syntax error. We notified the error inside _parse_update_parameters function
			if( ret == 0 )
				continue;

			command.parameter_length = ret;
			command.id = DYN_CONF_CMD_UPDATE;
			cmd_str = CMD_UPDATE_STR;
		}else{
			_reply( sock, CMD_SYNTAX_ERROR , "Does not support the command: %s", buffer );
			continue;
		}

		log_write( LOG_INFO, "Publish command id %d (%s)", command.id, cmd_str );

		//4: 2bytes of id + 2bytes of paramter_length
		ret = mmt_bus_publish( (char *) &command, 4 + command.parameter_length, NULL );

		switch( ret ){
		case MSG_BUS_OLD_MSG_NO_CONSUME:
			_reply( sock, MSG_BUS_OLD_MSG_NO_CONSUME, "Old message is not consumed. Need to wait then resend again." );
			break;
		case MMT_BUS_SUCCESS:
			_reply( sock, CMD_SUCCESS, "Successfully processed the command: %s", cmd_str );
			break;
		}

		continue;

	}while( true );

	close( sock );
}

static void _signal_handler( int type ){
	switch( type ){
	case SIGINT:

		log_write(LOG_INFO, "Received SIGINT. Exit dynamic configuration server.");
		close( socket_fd );
		unlink( address.sun_path );

		//intend to exit
		EXIT_NORMALLY();

		break;

	case SIGSEGV:
		log_write(LOG_ERR, "Segv signal received on control process!");
		log_execution_trace();

		//Auto restart when segmentation fault
		EXIT_THEN_RESTART_BY_PARENT();

		break;
	}
}

bool dynamic_conf_server_start_processing( const char* unix_domain_descriptor ){
	int  newsock_fd;
	struct sockaddr_un cli_addr;
	socklen_t sock_len = sizeof( cli_addr );

	//default signal to exit
	signal( SIGINT,  _signal_handler );
	signal( SIGSEGV, _signal_handler );

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
	printf("MMT-Probe is listening control commands on UNIX domain socket at %s", unix_domain_descriptor );

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
