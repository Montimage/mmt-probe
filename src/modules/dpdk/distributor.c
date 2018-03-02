/*
 * distributor.c
 *
 *  Created on: Feb 28, 2018
 *      Author: nhnghia
 */

#include "dpdk_capture.h"
#include "distributor.h"

distributor_t *distributor_create( unsigned int socket_id, uint16_t nb_workers ){
	if( nb_workers > DIST_MAX_WORKERS )
		rte_exit_failure("Cannot create distributor. Nb of workers is to big (must be less than %d", DIST_MAX_WORKERS );

	distributor_t *d = malloc( sizeof( distributor_t ));
	d->socket_id  = socket_id;
	d->nb_workers = nb_workers;
	d->nb_packets = 0;
	d->efd        = rte_efd_create("efd_distributor", DIST_NB_CONCURRENT_FLOWS,
			sizeof(uint32_t), 1 << socket_id, socket_id);
	if( d->efd == NULL )
		rte_exit_failure( "Cannot allocate EFD for distributor: %s (%d)", rte_strerror(rte_errno), rte_errno  );

	int i;
	char ring_name[100];
	//reset buffers of workers
	for( i=0; i<nb_workers; i++ ){
		snprintf(ring_name, sizeof( ring_name ), "d_r_%d", i);
		d->worker_buffers[i] = rte_ring_create( ring_name, DIST_BURST_SIZE * 2, socket_id,
				RING_F_SC_DEQ | RING_F_SP_ENQ );
	}

	//this ensures that no workers is assigned at the begining
	efd_value_t val = nb_workers + 1;
	uint32_t key;
	for( key=0; key<DIST_NB_CONCURRENT_FLOWS; key++ ){
		//
//		val = key % nb_workers;

		int ret = rte_efd_update( d->efd, socket_id, (void *)&key, (efd_value_t)val);
		if (ret < 0)
			rte_exit_failure( "Unable to add entry %u in EFD table\n", key);
	}

	return d;
}

static inline void _pause( uint16_t cycles ){
	rte_pause();
	uint64_t t = rte_rdtsc() + cycles;

	while (rte_rdtsc() < t)
		rte_pause();
}

static inline void _process_packets( distributor_t *d ){
	uint8_t target_worker_id;
	struct rte_ring *buffer;
	efd_value_t match[RTE_EFD_BURST_MAX];
	const void *key_ptrs[RTE_EFD_BURST_MAX];
	uint32_t    key_vals[RTE_EFD_BURST_MAX];
	int i, j, k;

	//the caller of this function ensures that
	// d->nb_packets  <= RTE_EFD_BURST_MAX
//	for( i=0; i<d->nb_packets; i++ ){
//		key_vals[i] = d->packets[i]->hash.usr;
//		key_ptrs[i] = (void *) &key_vals[i];
//	}
//
//	rte_efd_lookup_bulk( d->efd, d->socket_id, d->nb_packets,
//			(const void **) key_ptrs, match );

	uint16_t nb_unprocessed_packets = 0;
	struct rte_mbuf *unprocessed_packets[RTE_EFD_BURST_MAX];

	//for each packet
	for( i=0; i<d->nb_packets; i++ ){
//		target_worker_id = match[i];
		target_worker_id = d->packets[i]->hash.usr % d->nb_workers;

		//a new flow => attribute it to the one is being free
//		while( unlikely( target_worker_id >= d->nb_workers )){
//
//			//find a free worker
//			for( j=0; j<d->nb_workers; j ++ )
//				if( rte_ring_count( d->worker_buffers[ j ] ) == 0 ){ //< DIST_BURST_SIZE ){
//					target_worker_id = j;
//
//					//==> found one free worker <===
//
//					//assign all packets having the same key_val to this worker
//					for( k=i+1; k<d->nb_packets; k++ )
//						if( key_vals[k] == key_vals[i] )
//							match[k] = target_worker_id;
//
//					//update efd
//					rte_efd_update( d->efd, d->socket_id, key_ptrs[i], (efd_value_t)target_worker_id );
//
//					//break for, while
//					goto found_a_free_worker;
//				}
//
//			//all workers are busy
//			//=> waiting for a worker being free
//			_pause( 200 );
//			//break the loop by "goto found_a_free_worker"
//		}

		found_a_free_worker:

		//assign to a worker
		buffer = d->worker_buffers[ target_worker_id ];

		//the worker is busy ???
		if( unlikely( rte_ring_full( buffer ) )){
			//remember the unprocessed packets
			unprocessed_packets[ nb_unprocessed_packets++ ] = d->packets[i];
		}else
			rte_ring_enqueue( buffer, d->packets[i] );
	}

	//tell workers their packets to process
//	for( j=0; j<d->nb_workers; j++ )
//		d->worker_buffers[j].worker_count = d->worker_buffers[j].distributor_count;

	//retain the unprocessed packets
	for( i=0; i<nb_unprocessed_packets; i++ )
		d->packets[i] = unprocessed_packets[i];
	d->nb_packets = nb_unprocessed_packets;
}

void distributor_process_packets( distributor_t *d, struct rte_mbuf **bufs, uint16_t count ){
	int i=0;
	while( i<count ){
		//copy bufs to data;
		for( ; i<count && d->nb_packets < RTE_EFD_BURST_MAX; i++ ){
			d->packets[ d->nb_packets++ ] = bufs[i];
		}
		_process_packets( d );
	}
}

void distributor_send_pkt_to_all_workers( distributor_t *d, struct rte_mbuf *buf ){
	int i;
	for( i=0; i<d->nb_workers; i++ )
		rte_ring_enqueue( d->worker_buffers[i], buf );
}
