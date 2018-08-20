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

#define DIST_BURST_SIZE 256
#define DIST_MAX_WORKERS 64

struct worker_buffer{
	struct rte_mbuf *packets[ DIST_BURST_SIZE ];
	uint16_t nb_packets;
};

typedef struct distributor{
	struct rte_ring *worker_rings[ DIST_MAX_WORKERS ];

	struct worker_buffer *worker_buffers[ DIST_MAX_WORKERS ];

	struct rte_mbuf **packets;
	struct rte_mbuf **unprocessed_packets;
	uint16_t nb_packets;


	uint16_t nb_workers;
	unsigned int socket_id;
}distributor_t;

static inline void dpdk_pause( uint16_t cycles ){
	rte_pause();
	uint64_t t = rte_rdtsc() + cycles;

	while (rte_rdtsc() < t)
		rte_pause();
}

distributor_t *distributor_create( unsigned int socket_id, uint16_t nb_workers, unsigned worker_buffer_size );
void distributor_release( distributor_t *dis );

void distributor_process_packets( distributor_t *d, struct rte_mbuf **bufs, uint16_t count );

void distributor_send_pkt_to_all_workers( distributor_t *d, struct rte_mbuf *buf );

static inline int distributor_get_packets( distributor_t *d, uint16_t worker_id, struct rte_mbuf **bufs, unsigned burst_size ){
	return rte_ring_dequeue_burst( d->worker_rings[ worker_id ], (void *) bufs, burst_size, NULL );
}

#endif /* SRC_MODULES_DPDK_DISTRIBUTOR_H_ */
