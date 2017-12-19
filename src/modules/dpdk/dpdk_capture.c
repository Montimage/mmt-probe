/*
 * dpdk_capture.c
 *
 *  Created on: Dec 20, 2016
 *      Author: montimage
 */

#include <semaphore.h>

#ifndef DPDK_MODULE
#define DPDK_MODULE
#endif

#include "dpdk_capture.h"
#include "../../lib/worker.h"
#include "../../lib/alloc.h"

#define RX_RING_SIZE    4096 	/* Size for each RX ring*/
#define NUM_MBUFS       65535  /* Total size of MBUFS */
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE      128  	/* Burst size to receive packets from RX ring */

struct dpdk_worker_context_struct{
	sem_t semaphore;
};

/* Symmetric RSS hash key */
static uint8_t hash_key[52] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A

};

/* RX configuration struct */
static const struct rte_eth_rxconf rx_default_conf = {
		.rx_thresh = {
				.pthresh = 8,   /* Ring prefetch threshold */
				.hthresh = 8,   /* Ring host threshold */
				.wthresh = 0    /* Ring writeback threshold */
		},
		// .rx_free_thresh = 32,    /* Immediately free RX descriptors */
		.rx_drop_en     = 0
};

/* eth port configuration struct */
static const struct rte_eth_conf port_default_conf = {
		.rxmode = {
				//.max_rx_pkt_len = ETHER_MAX_LEN,
				.mq_mode        = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = ETHER_MAX_LEN,
				.split_hdr_size = 0,
				.header_split   = 0,   /**< Header Split disabled */
				.hw_ip_checksum = 0, /**< IP checksum offload disabled */
				.hw_vlan_filter = 0, /**< VLAN filtering disabled */
				.jumbo_frame    = 0,
				.hw_strip_crc   = 0,
		},
		.rx_adv_conf = {
				.rss_conf = {
						.rss_key     = hash_key,
						.rss_key_len = 52,
						.rss_hf      = ETH_RSS_PROTO_MASK
				},
		},
};

/**
 * Print statistic of captured packets given by DPDK
 * @param mmt_conf
 */
static inline void _print_dpdk_stats( uint8_t port_number ){
	struct rte_eth_stats stat;

	int ret = rte_eth_stats_get( port_number, &stat );

	if( ret ){
		log_write( LOG_WARNING, "Cannot get statistics from DPDK for port %d", port_number );
	}else{
		//get total packets
		uint64_t total_pkt = stat.ipackets + stat.imissed + stat.ierrors;

		log_write( LOG_INFO, "DPDK received %"PRIu64" packets, dropped %"PRIu64" (%.2f%%), error %"PRIu64" (%.2f%%)",
				total_pkt,
				stat.imissed,
				stat.imissed * 100.0 / total_pkt,
				stat.ierrors,
				stat.ierrors * 100.0 / total_pkt
		);
	}
}

static int _worker_thread( void *arg ){
	worker_context_t *worker_context = (worker_context_t *) arg;
	probe_context_t *probe_context   = worker_context->probe_context;
	int i;
	uint16_t avail_pkt_count;
	struct pkthdr pkt_header;
	//	struct timespec time_now;
	struct rte_mbuf *bufs[BURST_SIZE];

	const u_char* pkt_data;

	worker_on_start( worker_context );

	const uint8_t input_port = atoi( probe_context->config->input->input_source );

	pkt_header.user_args = NULL;

	/* Run until the application is quit or killed. */
	while ( likely( !probe_context->is_aborting )) {

		// Get burst of RX packets, from first port
		avail_pkt_count = rte_eth_rx_burst( input_port, worker_context->index, bufs, BURST_SIZE );

		if( avail_pkt_count == 0 ){
			//			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
		}else{
			//timestamp of a packet is the moment we retrieve it from buffer of DPDK
			gettimeofday(&pkt_header.ts, NULL);

			for (i = 0; i < avail_pkt_count; i++){
				pkt_header.len         = bufs[i]->pkt_len;
				pkt_header.caplen      = bufs[i]->data_len;
				//suppose that each packet comes after one micro-second
				pkt_header.ts.tv_usec += 1;

				pkt_data = (bufs[i]->buf_addr + bufs[i]->data_off);

				worker_process_a_packet( worker_context, &pkt_header, pkt_data );

				rte_pktmbuf_free( bufs[i] );
			}
		}
	}

	worker_on_stop( worker_context );

	//finish, wake up the main thread
	sem_post( &worker_context->dpdk->semaphore );

	return 0;
}


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline void _port_init( int port_number, probe_context_t *context ){
	struct rte_mempool *mbuf_pool;
	int ret, i;
	char pool_name[100];


	// Configure the Ethernet device: no tx, #thread_count rx
	ret = rte_eth_dev_configure(port_number, context->config->thread->thread_count, 0 , &port_default_conf);
	if( ret != 0 )
		rte_exit_failure( "Cannot configure port %d (%s)\n", port_number, rte_strerror(ret) );

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for( i = 0; i < context->config->thread->thread_count; i++ ) {
		snprintf( pool_name, sizeof( pool_name), "pool_%d", i );

		// Creates a new mempool in memory to hold the mbufs.
		mbuf_pool = rte_pktmbuf_pool_create( pool_name, NUM_MBUFS,
				MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

		if (mbuf_pool == NULL)
			rte_exit_failure( "Cannot create mbuf_pool for queue %d of port %d\n", i, port_number );

		ret = rte_eth_rx_queue_setup( port_number, i,
				//context->config->thread->thread_queue_packet_threshold,
				RX_RING_SIZE,
				rte_eth_dev_socket_id( port_number ),
				&rx_default_conf,
				mbuf_pool);

		if (ret < 0)
			rte_exit_failure( "Cannot init queue %d of port %d (%s)\n", i, port_number, rte_strerror(ret) );
	}

	/* Start the Ethernet port. */
	ret = rte_eth_dev_start( port_number );

	if (ret < 0)
		rte_exit_failure("Cannot start port %d\n", port_number );

	// Enable RX in promiscuous mode for the Ethernet device.
	rte_eth_promiscuous_enable( port_number );
}

static inline void _dpdk_capture_release( probe_context_t *context ){
	int i;
	for( i=0; i<context->config->thread->thread_count; i++ )
		worker_release( context->smp[i] );
	xfree( context->smp );
}

void dpdk_capture_start ( probe_context_t *context){

	uint8_t input_port;
	const unsigned total_of_cores  = rte_lcore_count(),
			master_lcore_id = rte_get_master_lcore();

	int i, lcore_id;

	if( context->config->thread->thread_count == 0 )
		rte_exit_failure("DPDK needs at least one thread to run");

	//we need at least one core for main thread and <n> cores for workers
	if ( total_of_cores < 1 + context->config->thread->thread_count )
		rte_exit_failure( "This application does not have "
				"enough cores to run this application, check threads assigned \n");

	// Initialize input port
	input_port = atoi( context->config->input->input_source );

	_port_init(input_port, context);

	context->smp = alloc( sizeof( worker_context_t ) * context->config->thread->thread_count );

	lcore_id = 0;
	i = 0;

	// Initialize the workers
	while ( i < context->config->thread->thread_count ){
		//put a worker on a core being different with main core
		if ( rte_lcore_is_enabled( lcore_id ) && lcore_id != master_lcore_id){

			context->smp[i] = worker_alloc_init();

			context->smp[i]->lcore_id      = lcore_id;
			context->smp[i]->index         = i;
			//keep a reference to its root
			context->smp[i]->probe_context = context;

			//for DPDK
			context->smp[i]->dpdk = alloc( sizeof( struct dpdk_worker_context_struct ));

			sem_init( &context->smp[i]->dpdk->semaphore, 0, 0 );

			//start worker
			rte_eal_remote_launch( _worker_thread, context->smp[i], lcore_id );
			i ++;
		}
		lcore_id ++ ;
	}

	// Waiting for all workers finish their jobs
	//rte_eal_mp_wait_lcore();
	for( i=0; i< context->config->thread->thread_count; i++ )
		sem_wait( & context->smp[i]->dpdk->semaphore );

	//all workers have been stopped

	worker_print_common_statistics( context );

	//statistic of DPDK
	_print_dpdk_stats( input_port );

	_dpdk_capture_release( context );
}
