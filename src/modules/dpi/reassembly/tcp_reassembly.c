/*
 * tcp_reassembly.c
 *
 *  Created on: Jun 15, 2018
 *          by: Huu Nghia Nguyen
 */

#include "tcp_reassembly.h"
#include "../../../lib/memory.h"

struct tcp_reassembly_struct{
	bool is_enable;
};
tcp_reassembly_t* tcp_reassembly_alloc_init( bool is_enable, mmt_handler_t *dpi_handler, int (*cb)(const ipacket_t *ipacket, void *user_args) ){
	if( is_enable )
		init_reassembly( dpi_handler, cb );
	tcp_reassembly_t *ret = mmt_alloc( sizeof( tcp_reassembly_t ));
	ret->is_enable = true;
	return ret;
}

void tcp_reassembly_close( tcp_reassembly_t *context ){
	if( context == NULL )
		return;
	close_reassembly();
	mmt_probe_free( context );
}
