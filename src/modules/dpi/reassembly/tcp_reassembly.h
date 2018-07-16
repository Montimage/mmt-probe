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

typedef struct tcp_reassembly_struct tcp_reassembly_t;

typedef void (*tcp_session_payload_callback_t)(const void *payload, uint32_t payload_len, void *user_args );

tcp_reassembly_t* tcp_reassembly_alloc_init( bool is_enable, mmt_handler_t *dpi_handler, tcp_session_payload_callback_t callback, void *user_args );

void tcp_reassembly_close(tcp_reassembly_t*);

#endif /* SRC_MODULES_DPI_REASSEMBLY_TCP_REASSEMBLY_H_ */
