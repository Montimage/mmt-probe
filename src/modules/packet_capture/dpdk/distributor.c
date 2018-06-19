/*
 * distributor.c
 *
 *  Created on: Feb 28, 2018
 *      Author: nhnghia
 */

#include "dpdk_capture.h"
#include "distributor.h"

distributor_t *distributor_create( unsigned int socket_id, uint16_t nb_workers, uint32_t worker_buffer_size ){
	if( nb_workers > DIST_MAX_WORKERS )
		rte_exit_failure("Cannot create distributor. Nb of workers is to big (must be less than %d", DIST_MAX_WORKERS );

	if( worker_buffer_size < DIST_BURST_SIZE )
		rte_exit_failure("Size of worker's buffers must be at least %d", DIST_BURST_SIZE );

	distributor_t *d = rte_malloc(NULL, sizeof( distributor_t ), RTE_CACHE_LINE_SIZE);
	d->socket_id  = socket_id;
	d->nb_workers = nb_workers;
	d->nb_packets = 0;
	d->packets             = rte_malloc(NULL, sizeof( void *) * DIST_BURST_SIZE, RTE_CACHE_LINE_SIZE);
	d->unprocessed_packets = rte_malloc(NULL, sizeof( void *) * DIST_BURST_SIZE, RTE_CACHE_LINE_SIZE);

	int i;
	char ring_name[100];
	//reset buffers of workers
	for( i=0; i<nb_workers; i++ ){
		d->worker_buffers[i] = rte_malloc( NULL, sizeof( struct worker_buffer ), RTE_CACHE_LINE_SIZE );
		d->worker_buffers[i]->nb_packets = 0;

		snprintf(ring_name, sizeof( ring_name ), "d_r_%d", i);
		d->worker_rings[i] = rte_ring_create( ring_name,
				worker_buffer_size,
				socket_id,
				RING_F_SC_DEQ | RING_F_SP_ENQ );
		if( d->worker_rings[i] == NULL )
			rte_exit_failure("Cannot create buffer for worker %d", i );
	}

	return d;
}

void distributor_release( distributor_t *dis ){
	if( dis == NULL )
		return;
	int i;

	rte_free( dis->packets );
	rte_free( dis->unprocessed_packets );

	for( i=0; i<dis->nb_workers; i++ ){
		rte_free( dis->worker_buffers[i] );
		rte_ring_free( dis->worker_rings[i] );
	}
	rte_free( dis );
}

static inline bool _is_full( const struct worker_buffer *buf ){
	return (buf->nb_packets == DIST_BURST_SIZE);
}

static inline void _process_packets( distributor_t *d ){
	uint8_t target_worker_id;
	struct worker_buffer *buffer;
	int i, j, k;

	uint16_t nb_unprocessed_packets = 0;

	//for each packet
	for( i=0; i<d->nb_packets; i++ ){
		//get ID of a worker that will process this packet
		target_worker_id = d->packets[i]->hash.usr;

		//get buffer of the worker
		buffer = d->worker_buffers[ target_worker_id ];

		//the worker is busy ???
		if( unlikely( _is_full( buffer )  ))
			//remember the unprocessed packets
			d->unprocessed_packets[ nb_unprocessed_packets++ ] = d->packets[i];
		else
			buffer->packets[ buffer->nb_packets ++ ] = d->packets[i];
	}

	//push to workers
	for( i=0; i<d->nb_workers; i++ )
		//if all packets in buffer are enqueued
		if( rte_ring_sp_enqueue_bulk(d->worker_rings[i],
				(void *) d->worker_buffers[i]->packets, d->worker_buffers[i]->nb_packets, NULL ) != 0 )
			//reset the buffer
			d->worker_buffers[i]->nb_packets = 0;

	//swap d->packets vs. d->unprocessed_packets
	struct rte_mbuf **tmp = d->packets;
	d->packets = d->unprocessed_packets;
	d->unprocessed_packets = tmp;

	//retain the unprocessed packets
	d->nb_packets = nb_unprocessed_packets;
}

void distributor_process_packets( distributor_t *d, struct rte_mbuf **bufs, uint16_t count ){
	int i=0;
	while( i<count ){

		//put bufs' pointers to data;
		for( ; i<count && d->nb_packets < DIST_BURST_SIZE; i++ ){
			//get ID of a worker that will process this packet
			bufs[i]->hash.usr %= d->nb_workers;

			d->packets[ d->nb_packets++ ] = bufs[i];
		}

		_process_packets( d );
	}
}

void distributor_send_pkt_to_all_workers( distributor_t *d, struct rte_mbuf *buf ){
	int i;
	for( i=0; i<d->nb_workers; i++ )
		//ensure the packet is sent to its worker
		while( rte_ring_enqueue( d->worker_rings[i], buf ) ){
			dpdk_pause( 1000 );
		}
}
