/*
 * tcp_reassembly.c
 *
 *  Created on: Jun 15, 2018
 *          by: Huu Nghia Nguyen
 */
#include "tcp_reassembly.h"
#include <tcpip/mmt_tcpip.h>

#include "../../../lib/memory.h"

struct tcp_reassembly_struct{
	tcp_session_payload_callback_t callback;
	void *user_args;
};
tcp_reassembly_t* tcp_reassembly_alloc_init( bool is_enable, mmt_handler_t *dpi_handler, tcp_session_payload_callback_t callback, void *user_args ){
	if( !is_enable || callback == NULL)
		return NULL;
	//call DPI function to activate the reassembly on TCP
	update_protocol( PROTO_TCP, TCP_ENABLE_REASSEMBLE );

	tcp_reassembly_t *ret = mmt_alloc_and_init_zero( sizeof( tcp_reassembly_t ));
	ret->user_args = user_args;
	ret->callback = callback;
	return ret;
}

void tcp_reassembly_close( tcp_reassembly_t *context ){
	if( context == NULL )
		return;
	mmt_probe_free( context );
}
