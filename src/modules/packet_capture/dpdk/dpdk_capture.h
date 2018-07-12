/*
 * dpdk_capture.h
 *
 *  Created on: Dec 14, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPDK_DPDK_CAPTURE_H_
#define SRC_MODULES_DPDK_DPDK_CAPTURE_H_

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <errno.h>


#include "../../../context.h"

/*
 * When having error during initialize DPDK, we need to exit normally the main processing process.
 * Thus the parent process will not recreate this child process to give control to user to be able to change some setting.
 */
#define rte_exit_failure( fm, ... ) do{                        \
	  log_write( LOG_ERR, fm,##__VA_ARGS__ );                  \
	  rte_exit( EXIT_SUCCESS, fm "\n",## __VA_ARGS__ );        \
   }while( 0 )


void dpdk_capture_start( probe_context_t *context );

#endif /* SRC_MODULES_DPDK_DPDK_CAPTURE_H_ */
