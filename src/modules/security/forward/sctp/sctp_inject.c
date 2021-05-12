/*
 * sctp.c
 *
 *  Created on: May 12, 2021
 *      Author: nhnghia
 *
 * This file implements the packet injection using SCTP:
 * - Once a packet arrives, its SCTP payload is forwarded using this implementation
 * So:
 * + work only with SCTP packets
 * + this injector works as a SCTP proxy
 *
 * - Need "-lsctp" when compiling
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

#include "../inject_packet.h"

struct inject_packet_context_struct{
	int client_fd;
	uint16_t nb_copies;
};

#define TARGET_PORT 38412
#define TARGET_IP   "127.0.0.5"

int _sctp_connect(){
	int conn_fd, ret;
	struct sockaddr_in servaddr = {
			.sin_family = AF_INET,
			.sin_port = htons( TARGET_PORT ),
			.sin_addr.s_addr = inet_addr( TARGET_IP ),
	};

	conn_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
	ASSERT( conn_fd >= 0, "Cannot create SCTP socket" );

	ret = connect(conn_fd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	ASSERT( ret >= 0, "Cannot connect to %s:%d using SCTP", TARGET_IP, TARGET_PORT );

	return conn_fd;
}

inject_packet_context_t* inject_packet_alloc( const probe_conf_t *probe_config ){


	const forward_packet_conf_t *conf = probe_config->forward_packet;
	inject_packet_context_t *context = mmt_alloc_and_init_zero( sizeof( struct inject_packet_context_struct ));
	context->client_fd = _sctp_connect();
	context->nb_copies = conf->nb_copies;
	return context;
}


static inline void _reconnect_sctp_if_need( inject_packet_context_t *context ){
	struct sctp_status status;
	int ret;
    int i = sizeof(status);
    ret = getsockopt( context->client_fd, SOL_SCTP, SCTP_STATUS, &status, (socklen_t *)&i);
    ASSERT( ret != 0, "Cannot get SCTP socket status");

    printf("\nSCTP Status:\n--------\n");
    printf("assoc id  = %d\n", status.sstat_assoc_id);
    printf("state     = %d\n", status.sstat_state);
    printf("instrms   = %d\n", status.sstat_instrms);
    printf("outstrms  = %d\n--------\n\n", status.sstat_outstrms);
}

int inject_packet_send_packet( inject_packet_context_t *context, const uint8_t *packet_data, uint16_t packet_size ){
	uint16_t nb_pkt_sent = 0;
	int ret, i;
	_reconnect_sctp_if_need( context );

	for( i=0; i<context->nb_copies; i++ ){
		//returns the number of bytes written on success and -1 on failure.
		ret = sctp_sendmsg( context->client_fd, packet_data,  packet_size, NULL, 0, 0, 0, 0, 0, 0 );
		if( ret > 0 )
			nb_pkt_sent ++;
	}
	return nb_pkt_sent;
}

void inject_packet_release( inject_packet_context_t *context ){
	if( !context )
		return;
	close(context->client_fd);

	mmt_probe_free( context );
}



