/*
 * malloc_ext.h
 *
 *  Created on: Aug 24, 2018
 *          by: Huu Nghia Nguyen
 *
 *  This is a wrapper of malloc.h
 *  This enables using DPDK memory allocation.
 *  The functions in this file must not be called before rte_eal_init.
 */

#ifndef SRC_LIB_MEMORY_EXT_H_
#define SRC_LIB_MEMORY_EXT_H_

/*
 * Do not use dpdk_malloc and dpdk_free as they are very slow.
 * Below is number of cycles (tested on server10ga)
 * to allocate and free a memory segment having a random size:
 * (see test/dpdk_alloc_perf.c)
 *
 * dpdk: 3436500.22, glib: 3936.20
 */

#ifdef DO_NOT_USE___DPDK_MODULE
//#ifdef DPDK_MODULE
	#include "../modules/packet_capture/dpdk/dpdk_malloc.h"

	#define mmt_alloc(x)               dpdk_malloc( x )
	#define mmt_probe_free(x)          dpdk_free( x )
	#define mmt_alloc_and_init_zero(x) dpdk_zalloc( x )

	#define mmt_strdup(x)              dpdk_strdup( x )
#else
	#include "malloc.h"
#endif

#endif /* SRC_LIB_MEMORY_EXT_H_ */
