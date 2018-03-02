/*
 * distributor.h
 *
 *  Created on: Feb 28, 2018
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPDK_DISTRIBUTOR_H_
#define SRC_MODULES_DPDK_DISTRIBUTOR_H_

#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_efd.h>
#include <rte_ring.h>

#define DIST_MAX_WORKERS 64
#define DIST_BURST_SIZE   8 //distribute maximally 8 packets to each reader
#define DIST_NB_CONCURRENT_FLOWS 1000000


typedef struct distributor{
	struct rte_ring *worker_buffers[ DIST_MAX_WORKERS ];

	struct rte_mbuf *packets[RTE_EFD_BURST_MAX];
	uint16_t nb_packets;

	struct rte_efd_table  *efd;
	uint16_t nb_workers;
	unsigned int socket_id;
}distributor_t;

distributor_t *distributor_create( unsigned int socket_id, uint16_t nb_workers );

void distributor_process_packets( distributor_t *d, struct rte_mbuf **bufs, uint16_t count );

void distributor_send_pkt_to_all_workers( distributor_t *d, struct rte_mbuf *buf );

//int distributor_get_packets( distributor_t *d, uint16_t worker_id, struct rte_mbuf **bufs );
static inline int distributor_get_packets( distributor_t *d, uint16_t worker_id, struct rte_mbuf **bufs ){
	return rte_ring_dequeue_burst( d->worker_buffers[ worker_id ], (void *) bufs, DIST_BURST_SIZE, NULL );
}

#endif /* SRC_MODULES_DPDK_DISTRIBUTOR_H_ */
