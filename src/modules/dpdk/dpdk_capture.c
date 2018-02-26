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

#include <rte_random.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_distributor.h>

#include <signal.h>
#include <unistd.h> //alarm

#include "dpdk_capture.h"
#include "../../lib/worker.h"
#include "../../lib/alloc.h"

#define RX_DESCRIPTORS    4096 	/* Size for RX ring*/
#define RX_BURST_SIZE      256  	/* Burst size to receive packets from RX ring */

#define MBUF_CACHE_SIZE    512

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

//input parameter of each worker thread
struct dpdk_worker_context_struct{
	struct rte_distributor *distributor;
	sem_t semaphore;
}__rte_cache_aligned;

//input parameter of reader and distributor threads
struct param{
	struct rte_distributor *distributor;
	struct rte_ring  *rx_ring;
	probe_context_t *probe_context;
}__rte_cache_aligned;


struct timeval64{
	uint32_t tv_sec;
	uint32_t tv_usec;
}__rte_cache_aligned;


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
				.mq_mode        = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = ETHER_MAX_LEN,
				.split_hdr_size = 0,
				.header_split   = 0, /**< Header Split disabled */
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
	worker_context_t *worker_context    = (worker_context_t *)arg;
	const probe_conf_t *config          = worker_context->probe_context->config;
	struct rte_distributor *distributor = worker_context->dpdk->distributor;
	int i;
	struct pkthdr pkt_header;
	const u_char* pkt_data;

	worker_on_start( worker_context );

	pkt_header.user_args = NULL;

	//The mbufs pointer array to be filled in (up to 8 packets)
	struct rte_mbuf *bufs[8] __rte_cache_aligned;

	unsigned int worker_id = worker_context->index;


	time_t now = time( NULL );

	uint32_t next_sample_ts = now + config->stat_period;
	uint32_t next_stat_ts   = now + config->outputs.file->output_period;

	bool is_continuous = true;
	/* Run until the application is quit or killed. */
	while ( likely( is_continuous )) {
		// Get burst of RX packets, from first port
		int nb_rx = rte_distributor_get_pkt( distributor, worker_id, bufs, NULL, 0 );

		if( nb_rx <= 0 ){
//			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
		}else {

			//last packet is special one to tell worker exist
			if( unlikely( bufs[ nb_rx - 1 ]->udata64 == 0 )){

				//confirm i-th worker is existing
				bufs[ nb_rx - 1 ]->udata64 = worker_id;

				//tell distributor that the worker is existing
				rte_distributor_return_pkt( distributor, worker_id, &bufs[ nb_rx - 1 ], 1 );
				is_continuous = false;
				nb_rx --;
			}

			for (i = 0; i < nb_rx; i++){
				pkt_header.len         = bufs[i]->pkt_len;
				pkt_header.caplen      = bufs[i]->data_len;
				struct timeval64 *t   = (struct timeval64 *) & bufs[i]->udata64;
				pkt_header.ts.tv_sec  = t->tv_sec;
				pkt_header.ts.tv_usec = t->tv_usec;

				//packet data
				pkt_data = (bufs[i]->buf_addr + bufs[i]->data_off);

				worker_process_a_packet( worker_context, &pkt_header, pkt_data );

				//do a small processing
//				uint64_t x = rte_rdtsc() + 1000 + worker_id*200;
//				while (rte_rdtsc() < x)
//					rte_pause();

				//after processing packet, we need to free its memory in mempool
				// to have place for others coming
				rte_pktmbuf_free( bufs[i] );
			}
		}

		now = time( NULL );

		//statistic periodically
		if( now >= next_stat_ts  ){
			next_stat_ts += config->stat_period;
			//call worker
			worker_on_timer_stat_period( worker_context );
		}

		//if we need to sample output file
		if( config->outputs.file->is_sampled && now >=  next_sample_ts ){
			next_sample_ts += config->outputs.file->output_period;
			//call worker
			worker_on_timer_sample_file_period( worker_context );
		}
	}

	worker_on_stop( worker_context );

	//finish, wake up the main thread
	sem_post( &worker_context->dpdk->semaphore );

	return 0;
}


static inline void _exit_worker( struct rte_distributor *distributor, uint16_t total_workers){
	int i;
	struct rte_mbuf *buf;

	//create mempool and then, a dummy packet
	struct rte_mempool *mempool = rte_pktmbuf_pool_create( "*", 1, 1, 0, 0, rte_socket_id() );
	struct rte_mbuf *packet = rte_pktmbuf_alloc( mempool );

	bool *alive_workers = alloc( sizeof( bool ) * total_workers );
	//suppose that all workers are working
	for( i=0; i<total_workers; i++ )
		alive_workers[i] = true;

	//===> send special packet to each worker to tell them to exit <=====
	while( total_workers > 0 ){
		rte_distributor_clear_returns( distributor );

		packet->udata64  = 0; //this is a signal to tell workers to exit
		//expect that the hash number is different
		//=> the packet will be distributed to different worker on each iteration of while-loop
		packet->hash.usr = rte_rand();

		//distribute the packet
		rte_distributor_process( distributor, &packet, 1 );
		rte_distributor_process( distributor, NULL, 0);
		//rte_distributor_flush( distributor );

		//waiting for a worker exit
		if( rte_distributor_returned_pkts( distributor, &buf, 1) > 0 ){
			//when received a dummy packet, a worker will confirm by assigning its id to udata64
			uint64_t confirmed_worker_id = buf->udata64;

			//check if having a confirmation
			if( confirmed_worker_id < total_workers && alive_workers[ confirmed_worker_id ]){
				total_workers --;
				alive_workers[ confirmed_worker_id ] = false;
			}
		}
	}
	//=====> all workers are informed to exit <========

	//free b & p
	rte_pktmbuf_free( packet );
	rte_mempool_free( mempool );
}

static int _distributor_thread( void *arg ){
	int i;
	bool is_continuous = true;
	struct rte_mbuf *bufs[RX_BURST_SIZE*2];

	struct param *param = (struct param *) arg;

	struct rte_ring *ring               = param->rx_ring;
	struct rte_distributor *distributor = param->distributor;

	uint64_t drop_pkts = 0, total_pkts = 0;

	time_t flush_time, now;
	flush_time = time( &now );

	/* Run until the distributor received a null packet. */
	while ( likely( is_continuous )) {
		// Get burst of RX packets, from first port
		uint32_t nb_rx = rte_ring_sc_dequeue_burst( ring, (void *)bufs, RX_BURST_SIZE*2, NULL );
		if( unlikely( nb_rx == 0 )){
//			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );

			//if there are no packets ==> wake up workers each second
			time( &now );
			if( now > flush_time ){
				//Flush out all non-full cache-lines to workers
				rte_distributor_process( distributor, NULL, 0 );
				flush_time = now;
			}
		} else {
			//received a null message => exit
			if( unlikely( bufs[ nb_rx - 1 ] == NULL )){
				nb_rx --;
				is_continuous = false; //exit while loop
			}

			total_pkts += nb_rx;

			//give packets to distributor
			int nb_proc = rte_distributor_process( distributor, bufs, nb_rx );

			//cannot process all packets => free the ones being unprocessed
			if( unlikely( nb_proc < nb_rx )){
				drop_pkts += nb_rx - nb_proc;
				while( nb_proc < nb_rx )
					rte_pktmbuf_free( bufs[nb_proc ++] );
			}
		}
	}

	log_write(LOG_INFO, "Distributor received %"PRIu64" pkt, dropped %"PRIu64" pkt (%6.3f %%)",
				total_pkts, drop_pkts, (drop_pkts == 0? 0 : drop_pkts*100.0 / total_pkts ));

	rte_distributor_flush( distributor );

	_exit_worker( distributor, param->probe_context->config->thread->thread_count );

	return 0;
}

static int _reader_thread( void *arg ){
	int i;
	uint16_t nb_rx;
	struct timeval time_now;
	struct rte_mbuf *bufs[RX_BURST_SIZE];

	struct param *param = (struct param *) arg;

	probe_context_t *probe_context = param->probe_context;


	const uint8_t input_port = atoi( probe_context->config->input->input_source );
	struct rte_ring *ring    = param->rx_ring;


	//redear should be run on lcore having the same socket with the on of its NIC
	if (rte_eth_dev_socket_id( input_port) > 0 &&
			rte_eth_dev_socket_id( input_port ) != rte_socket_id())
		log_write(LOG_WARNING, "Reader of port %u is on remote NUMA node to "
						"RX thread. Performance will not be optimal.",
						input_port );

	//statistic variables
	uint64_t total_pkts = 0, total_bytes = 0, drop_pkts = 0;

	/* Run until the application is quit or killed. */
	while ( likely( !probe_context->is_aborting )) {
		// Get burst of RX packets, from first port
		nb_rx = rte_eth_rx_burst( input_port, 0, bufs, RX_BURST_SIZE );

		if( unlikely( nb_rx == 0 )){
//			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
		} else {
			//total received packets
			total_pkts += nb_rx;

			//timestamp of a packet is the moment we retrieve it from buffer of DPDK
			gettimeofday(&time_now, NULL);

			struct timeval64 *t;

			//for each received packet,
			// we remember the moment the packet is received
			for (i = 0; i < nb_rx; i++){
				//cumulate total data this reader received
				total_bytes += bufs[i]->data_len;

				//tell distributor uses rss hash as flow id
				bufs[i]->hash.usr = bufs[i]->hash.rss;

				//encode a timval into a number of 64bits
				t = (struct timeval64 *) &bufs[i]->udata64;
				t->tv_sec  = time_now.tv_sec;
				//suppose that each packet arrives after one microsecond
				t->tv_usec = time_now.tv_usec + i;
			}

			uint32_t sent = rte_ring_sp_enqueue_burst(ring, (void*)bufs, nb_rx, NULL);

			//ring is full
			if( unlikely( sent < nb_rx )){
				drop_pkts += nb_rx - sent;
				while( sent < nb_rx )
					rte_pktmbuf_free( bufs[sent ++] );
			}
		}
	}

	log_write(LOG_INFO, "Reader received %"PRIu64" pkt (%"PRIu64" B), dropped %"PRIu64" pkt (%6.3f %%)",
			total_pkts, total_bytes, drop_pkts, (drop_pkts == 0? 0: drop_pkts*100.0 / total_pkts) );

	//enqueue a null message to ring to tell the distributor to exit
	//while loop ensures that the NULL obj is enqueued
	while( rte_ring_sp_enqueue( ring, NULL ) != 0 )
			rte_delay_ms(1);

	return 0;
}
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline void _port_init( int input_port, probe_context_t *context, struct param *param ){

	struct rte_mempool *mbuf_pool;
	char name[100];
	unsigned socket_id = rte_eth_dev_socket_id( input_port );
	uint16_t nb_rx_queues = 1; //context->config->thread->thread_count

	// Configure the Ethernet device: no tx
	int ret = rte_eth_dev_configure(input_port, nb_rx_queues, 0 , &port_default_conf);
	if( ret != 0 )
		rte_exit_failure( "Cannot configure port %d (%s)\n", input_port, rte_strerror(ret) );

	uint16_t nb_rxd = RX_DESCRIPTORS, nb_txd = 0;

	// Creates a new mempool in memory to hold the mbufs.
	snprintf( name, sizeof( name), "pool_%d", input_port );
	mbuf_pool = rte_pktmbuf_pool_create( name,
			context->config->thread->thread_queue_packet_threshold //ring
			+ nb_rx_queues*(nb_rxd*2)  //nic queue
			+ RX_BURST_SIZE*2    //reader
			+ RX_BURST_SIZE*16    //distributor
			- 1,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

	if (mbuf_pool == NULL)
		rte_exit_failure( "Cannot create mbuf_pool for port %d\n", input_port );

	//update nb of descriptors
	ret = rte_eth_dev_adjust_nb_rx_tx_desc( input_port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit_failure( "Cannot adjust number of descriptors for port=%d: %s\n",
				input_port, rte_strerror( ret ));
	else
		log_write( LOG_INFO, "Adjust number of rx descriptors of port %d to %d",
				input_port, nb_rxd );

	// Allocate and set up the first RX queue
	ret = rte_eth_rx_queue_setup( input_port,
			0,
			RX_DESCRIPTORS,
			socket_id,
			&rx_default_conf,
			mbuf_pool);

	if (ret < 0)
		rte_exit_failure( "Cannot init queue of port %d (%s)\n",
				input_port, rte_strerror(ret) );

	//create a ring that is a buffer between reader and distributor:
	// reader ==> (ring) ===> distributor
	snprintf( name, sizeof( name), "ring_%d", input_port );
	//TODO: check context->config->thread->thread_queue_packet_threshold is power of 2
	param->rx_ring = rte_ring_create( name,
			context->config->thread->thread_queue_packet_threshold,
			socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);

	if ( param->rx_ring == NULL )
		rte_exit_failure( "Cannot init ring of port %d (%s). ",
				//"Either increase the hugepage size or decrease ring size.\n"
				input_port, rte_strerror(ret) );

	//init distributor
	snprintf( name, sizeof( name), "distributor_%d", input_port );
	param->distributor = rte_distributor_create( name, socket_id,
			//The maximum number of workers that will request packets from this distributor
			context->config->thread->thread_count,
			RTE_DIST_ALG_BURST );

	if( param->distributor == NULL)
		rte_exit_failure( "Cannot create distributor for port %d (%s)\n",
				input_port, rte_strerror(ret) );

	// Start the Ethernet port.
	ret = rte_eth_dev_start( input_port );

	if (ret < 0)
		rte_exit_failure("Cannot start port %d (%s)\n", input_port, rte_strerror( ret ) );

	// Enable RX in promiscuous mode for the Ethernet device.
	rte_eth_promiscuous_enable( input_port );
}

static inline void _dpdk_capture_release( probe_context_t *context ){
	int i;
	for( i=0; i<context->config->thread->thread_count; i++ )
		worker_release( context->smp[i] );
	xfree( context->smp );
}

static void _print_stats(int type) {
	int port = 0;
	struct rte_eth_stats stat;
	rte_eth_stats_get( port, &stat );

	static uint64_t total_pkt = 0, total_drop = 0, total_data = 0;
	static uint32_t index = 0;

	uint64_t pool_used = 0, pool_total = 0;
	struct rte_mempool *pool = rte_mempool_lookup( "pool_0" );
	if( pool ){
		pool_used  = rte_mempool_in_use_count( pool );
		pool_total = pool->size;
	}

//	if( stat.imissed > total_drop )
//			printf("\ndropped : %"PRIu64"\n", stat.imissed - total_drop );
	printf(" %u: %'12ld bps, %'10ld pps, drop %'7ld pps (%5.2f%%), mpool %'10lu/ %'10lu\n",
			index++,
			(stat.ibytes - total_data)*8, (stat.ipackets - total_pkt),
			(stat.imissed - total_drop), (stat.imissed - total_drop) * 100.0 / (stat.ipackets+stat.imissed - total_drop - total_pkt),
			pool_used,
			pool_total);
//	int i;
//	for( i=0; i<context->thread_nb; i++ )
//		printf("   %2d : %'8ld pps, drop: %'8ld pps\n", i, stat.q_ipackets[i], stat.q_errors[i] );
	total_pkt = stat.ipackets;
	total_data = stat.ibytes;
	total_drop = stat.imissed;

	//rte_eth_stats_reset( port );
	alarm( 1 );
}

void dpdk_capture_start ( probe_context_t *context){

	uint8_t input_port;
	const unsigned total_of_cores  = rte_lcore_count();

	int i, lcore_id, ret;

	if(  context->config->thread->thread_count == 0 )
		rte_exit_failure("Number of threads must be greater than 0");

	//we need at least:
	// - one core for main thread
	// - one core for reader
	// - one core for distributor, and
	// - n cores for workers
	if ( total_of_cores < 3 + context->config->thread->thread_count )
		rte_exit_failure( "This application does not have "
				"enough cores to run this application. It needs at least %d lcores\n",
				3 + context->config->thread->thread_count);

	// Initialize input port
	input_port = atoi( context->config->input->input_source );

	struct param param;
	param.distributor = NULL;
	param.rx_ring     = NULL;
	param.probe_context = context;
	_port_init(input_port, context, &param );

	context->smp = alloc( sizeof( worker_context_t ) * context->config->thread->thread_count );

	lcore_id = 0;
	i = 0;

	// Initialize the workers
	for( i=0; i< context->config->thread->thread_count; i++ ){
		//put a worker on a core being different with main core
		lcore_id = rte_get_next_lcore( lcore_id, true, true );

		context->smp[i] = worker_alloc_init();

		//general part
		context->smp[i]->lcore_id      = lcore_id;
		context->smp[i]->index         = i;
		//keep a reference to its root
		context->smp[i]->probe_context = context;

		//for DPDK
		context->smp[i]->dpdk = alloc( sizeof( struct dpdk_worker_context_struct ));
		sem_init( &context->smp[i]->dpdk->semaphore, 0, 0 );
		context->smp[i]->dpdk->distributor = param.distributor;

		//start worker
		ret = rte_eal_remote_launch( _worker_thread, context->smp[i], lcore_id );
		if( ret != 0 )
			rte_exit_failure("Cannot start worker %d. The remote lcore is not in a WAIT state", i);
	}

	//start distributor
	//find an available lcore for distributor
	lcore_id = rte_get_next_lcore( lcore_id, true, true );
	ret = rte_eal_remote_launch( _distributor_thread, &param, lcore_id );
	if( ret != 0 )
		rte_exit_failure("Cannot start distributor. The remote lcore is not in a WAIT state");

	//start reader
	//ensure that reader and distributor run on 2 different lcores
	lcore_id = rte_get_next_lcore( lcore_id, true, true );
	ret = rte_eal_remote_launch( _reader_thread, &param, lcore_id );
	if( ret != 0 )
		rte_exit_failure("Cannot start reader. The remote lcore is not in a WAIT state");

	//print stat each second
	signal( SIGALRM, _print_stats );
	alarm( 1 );

	// Waiting for all workers finish their jobs


	//rte_eal_mp_wait_lcore();
	for( i=0; i< context->config->thread->thread_count; i++ )
		sem_wait( & context->smp[i]->dpdk->semaphore );

	//====> all workers have been stopped <====//

	//statistic of each worker
	worker_print_common_statistics( context );

	//statistic of DPDK
	_print_dpdk_stats( input_port );

	_dpdk_capture_release( context );
	fflush( stdout );
}
