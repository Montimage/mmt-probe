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

#ifdef DPDK_MODULE
	#include "../modules/packet_capture/dpdk/dpdk_malloc.h"

	#define mmt_alloc(x)               dpdk_malloc( x )
	#define mmt_probe_free(x)          dpdk_free( x )
	#define mmt_alloc_and_init_zero(x) dpdk_zalloc( x )

	#define mmt_strdup(x)              dpdk_strdup( x )
#else
	#include "malloc.h"
#endif

#endif /* SRC_LIB_MEMORY_EXT_H_ */
