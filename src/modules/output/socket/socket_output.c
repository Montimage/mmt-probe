/*
 * socket_output.c
 *
 *  Created on: May 30, 2018
 *          by: Huu Nghia Nguyen
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>

#include "socket_output.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc.h"

struct socket_output_struct{
	int unix_socket_fd;
	int internet_socket_fd;
};

#define NO_SOCKET_FD -1

static inline int _create_internet_client_socket( const char *host_name, uint16_t port, bool is_tcp_socket ){
	int fd;
	struct sockaddr_in server;
	struct hostent *hostp;
	char ip[16];

	fd = socket(AF_INET, is_tcp_socket? SOCK_STREAM : SOCK_DGRAM, 0);
	if ( fd < 0) {
		log_write(LOG_ERR, "Cannot open Internet domain socket: %s", strerror(errno));
		return NO_SOCKET_FD;
	}

	memset( &server, 0, sizeof(server) );
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr( host_name );
	server.sin_port = htons( port );

	/* When passing the host name of the server as a */
	/* parameter to this program, use the gethostbyname() */
	/* function to retrieve the address of the host server. */
	if( server.sin_addr.s_addr == (unsigned long) INADDR_NONE){
		// get host address
		hostp = gethostbyname( host_name );

		if(hostp == NULL){
			log_write( LOG_ERR, "Not found hostname %s: %s", host_name, strerror(errno));

			close( fd );
			return NO_SOCKET_FD;
		}

		memcpy(&server.sin_addr, hostp->h_addr, sizeof(server.sin_addr));

		inet_ntop(AF_INET, &server.sin_addr, ip, sizeof(ip));
		log_write( LOG_INFO, "IP of %s is %s", host_name, ip );
	}

	/* Now connect to the server */
	if( connect( fd, (struct sockaddr*)&server, sizeof(server)) < 0) {
		log_write( LOG_ERR, "Cannot connect to '%s:%d': %s", host_name, port, strerror(errno) );
		return NO_SOCKET_FD;
	}
	return fd;
}


static inline int _create_unix_client_socket( const char *descriptor ){
	int fd;
	struct sockaddr_un server;

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		log_write( LOG_ERR, "Cannot open UNIX domain socket: %s", strerror( errno ));
		return NO_SOCKET_FD;
	}

	memset( &server, 0, sizeof(server) );
	server.sun_family = AF_UNIX;
	strcpy( server.sun_path, descriptor );

	if( connect(fd, (struct sockaddr *) &server, sizeof( server )) < 0) {
		close( fd );
		log_write( LOG_ERR, "Cannot connect to '%s': %s", descriptor, strerror(errno));
		return NO_SOCKET_FD;
	}
	return fd;
}

socket_output_t* socket_output_init( const socket_output_conf_t *config ){
	if( config->is_enable == false )
		return NULL;

	socket_output_t *ret = mmt_alloc_and_init_zero( sizeof( socket_output_t ));

	if( config->socket_type == SOCKET_TYPE_ANY || config->socket_type == SOCKET_TYPE_UNIX )
		ret->unix_socket_fd = _create_unix_client_socket( config->unix_socket_descriptor );
	else
		ret->unix_socket_fd = NO_SOCKET_FD;

	if( config->socket_type == SOCKET_TYPE_ANY || config->socket_type == SOCKET_TYPE_TCP || config->socket_type == SOCKET_TYPE_UDP)
		ret->internet_socket_fd = _create_internet_client_socket( config->internet_socket.host_name, config->internet_socket.port_number, config->socket_type != SOCKET_TYPE_UDP );
	else
		ret->internet_socket_fd = NO_SOCKET_FD;
	return ret;
}

bool socket_output_send( socket_output_t *context, const char *msg ){
	char m[MAX_LENGTH_REPORT_MESSAGE];
	size_t len = snprintf(m, MAX_LENGTH_REPORT_MESSAGE, "%s\n", msg);
	bool ret = false;
	if( context->unix_socket_fd != NO_SOCKET_FD ){
		//ret |= send( context->unix_socket_fd, m, len, MSG_WAITALL ) != -1;
		ret |= write( context->unix_socket_fd, m, len ) != -1;
	}
	if( context->internet_socket_fd != NO_SOCKET_FD ){
		//ret |= send( context->internet_socket_fd, m, len, MSG_DONTWAIT ) != -1;
		ret |= write( context->internet_socket_fd, m, len ) != -1;
	}
	return ret;
}

void socket_output_release( socket_output_t *context ){
	if( context == NULL )
		return;
	if( context->unix_socket_fd != NO_SOCKET_FD )
		close( context->unix_socket_fd );
	if( context->internet_socket_fd != NO_SOCKET_FD )
		close( context->internet_socket_fd );
	mmt_probe_free( context );
}
