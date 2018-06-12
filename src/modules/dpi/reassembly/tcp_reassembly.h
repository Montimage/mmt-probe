/*
 * tcp_reassembly.h
 *
 *  Created on: Jun 8, 2018
 *          by: Huu Nghia Nguyen
 */

#ifndef SRC_MODULES_DPI_REASSEMBLY_TCP_REASSEMBLY_H_
#define SRC_MODULES_DPI_REASSEMBLY_TCP_REASSEMBLY_H_

#include <stdbool.h>
#include <mmt_core.h>
#include <mmt_reassembly.h>

static inline void tcp_reassembly_alloc_init( bool is_enable, mmt_handler_t *dpi_handler, int (*cb)(const ipacket_t *ipacket, void *user_args) ){
	if( is_enable )
		init_reassembly( dpi_handler, cb );
}

static inline void tcp_reassembly_release(){
	close_reassembly();
}

#endif /* SRC_MODULES_DPI_REASSEMBLY_TCP_REASSEMBLY_H_ */
