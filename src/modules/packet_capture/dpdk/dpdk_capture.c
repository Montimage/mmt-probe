/*
 * dpdk_capture.c
 *
 *  Created on: Dec 20, 2016
 *      Author: montimage
 *
 * We use:
 * - 1 thread for Reader to read packets from NIC and put them into a queue Q
 * - 1 thread for Distributer to read packets from queue Q and distribute them to corresponding queue of each Worker
 * - n thread for Worker to read packets form its queue, process packets, and output statistic information
 *
 *     ________       _____________     ==> [ Worker ]
 *    |        |     |             |   ||=> [ Worker ]
 * ==>| Reader | ==> | Distributer | =====> [ Worker ]
 *    |________|     |_____________|   ||=> [ Worker ]
 *                                      ..............
 */

#ifndef DPDK_MODULE
#define DPDK_MODULE
#endif

#include <semaphore.h>

#include <rte_random.h>
#include <rte_ethdev.h>
#include <rte_prefetch.h>
#include <rte_distributor.h>
#include <rte_ip.h>

#include <signal.h>
#include <unistd.h> //alarm

#include "dpdk_capture.h"
#include "distributor.h"

#include "../../../worker.h"
#include "../../../lib/memory.h"

#define RX_DESCRIPTORS         4096 	/* Size for RX ring*/
#define READER_BURST_SIZE       512  	/* Burst size to receive packets from RX ring */
#define DISTRIBUTOR_BURST_SIZE  256
#define MBUF_CACHE_SIZE         512

#define READER_QUEUE_SIZE       pow( 2, 21 )
#define WORKER_QUEUE_SIZE       512
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
	struct distributor *distributor;
	sem_t semaphore;
}__rte_cache_aligned;

//input parameter of reader and distributor threads
struct param{
	struct distributor *distributor;
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
		log_write_dual( LOG_WARNING, "Cannot get statistics from DPDK for port %d", port_number );
	}else{
		//get total packets
		uint64_t total_pkt = stat.ipackets + stat.imissed + stat.ierrors;

		log_write_dual( LOG_INFO, "DPDK received %"PRIu64" packets, dropped %"PRIu64" (%.2f%%), error %"PRIu64" (%.2f%%)",
				total_pkt,
				stat.imissed,
				stat.imissed * 100.0 / total_pkt,
				stat.ierrors,
				stat.ierrors * 100.0 / total_pkt
		);
	}
}

static int _worker_thread( void *arg ){
	worker_context_t *worker_context = (worker_context_t *)arg;
	const probe_conf_t *config       = worker_context->probe_context->config;
	struct distributor *distributor  = worker_context->dpdk->distributor;
	int i;
	struct pkthdr pkt_header __rte_cache_aligned;
	const u_char* pkt_data;

	worker_on_start( worker_context );

	pkt_header.user_args = NULL;

	//The mbufs pointer array to be filled in (up to 8 packets)
	struct rte_mbuf *bufs[64] __rte_cache_aligned;
	unsigned burst_size = 64;

	unsigned int worker_id = worker_context->index;


	time_t next_stat_ts = 0; //moment we need to do statistic
	time_t next_output_ts = 0; //moment we need flush output to channels
	time_t now; //current timestamp that is either
	//- real timestamp of system when running online
	//- packet timestamp when running offline

	now = time( NULL );
	next_stat_ts   = now + config->stat_period;
	next_output_ts = now + config->outputs.cache_period;

	volatile bool is_continuous = true;
	/* Run until the application is quit or killed. */
	while ( likely( is_continuous )) {
		// Get burst of RX packets, from first port
//		int nb_rx = rte_distributor_get_pkt( distributor, worker_id, bufs, NULL, 0 );
		int nb_rx = distributor_get_packets( distributor, worker_id, bufs, burst_size );

		if( nb_rx <= 0 ){
			//nanosleep( (const struct timespec[]){{0, 1000}}, NULL );
			dpdk_pause( 200 );
		}else {

			//last packet is special one to tell worker exist
			if( unlikely( bufs[ nb_rx - 1 ] == NULL)){
				is_continuous = false;
				nb_rx --;
			}

			for (i = 0; i < nb_rx; i++){
				pkt_header.len         = bufs[i]->pkt_len;
				pkt_header.caplen      = bufs[i]->data_len;
				//decode timestamp
				struct timeval64 *t   = (struct timeval64 *) & bufs[i]->udata64;
				pkt_header.ts.tv_sec  = t->tv_sec;
				pkt_header.ts.tv_usec = t->tv_usec;

				//get packet data
				pkt_data = (bufs[i]->buf_addr + bufs[i]->data_off);

				//process packet
				worker_process_a_packet( worker_context, &pkt_header, pkt_data );

				//TODO: this is to test only
				//do a small processing
//				dpdk_pause( 1000 );

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
		if( config->outputs.file->is_sampled && now >=  next_output_ts ){
			next_output_ts += config->outputs.cache_period;
			//call worker to flush statistic information to output channels (file, mongo, ..)
			worker_on_timer_sample_file_period( worker_context );
		}
	}

	worker_on_stop( worker_context );

	//finish, wake up the main thread
	sem_post( &worker_context->dpdk->semaphore );

	return 0;
}

static int _distributor_thread( void *arg ){
	int i;
	volatile bool is_continuous = true;
	struct rte_mbuf *bufs[DISTRIBUTOR_BURST_SIZE];

	struct param *param = (struct param *) arg;

	struct rte_ring *ring               = param->rx_ring;
	struct distributor *distributor = param->distributor;

	/* Run until the distributor received a null packet. */
	while ( likely( is_continuous )) {
		uint32_t nb_rx = rte_ring_sc_dequeue_burst( ring, (void *)bufs, DISTRIBUTOR_BURST_SIZE, NULL );
		if( unlikely( nb_rx == 0 )){
			//we need a small pause here -> reader_thread can easily to insert packet to queue
			//at 14Mpps -> 1 packet consumes 300 cycles
			//=> sleep 20 packets
			dpdk_pause( 5000 );
		} else {

			//received a null message => exit
			if( unlikely( bufs[ nb_rx - 1 ] == NULL )){
				nb_rx --;
				is_continuous = false; //exit while loop
			}

			//give packets to distributor
			distributor_process_packets( distributor, bufs, nb_rx );
		}
	}

	//send a NULL packet to all workers to tell them to exit
	distributor_send_pkt_to_all_workers( distributor, NULL );

	return 0;
}


static inline void _print_traffic_statistics( probe_context_t *context, const struct timeval *now ){
	int port = atoi( context->config->input->input_source );
	struct rte_eth_stats stat;
	rte_eth_stats_get( port, &stat );

	context->traffic_stat.nic.receive = stat.ipackets;
	context->traffic_stat.nic.drop    = stat.imissed + stat.ierrors;

	context_print_traffic_stat(context, now);
}

/**
 * This is Reader thread.
 * It receives packets from NIC then forward them to Distributer
 */
static int _reader_thread( void *arg ){
	int i;
	uint16_t nb_rx __rte_cache_aligned;
	struct timeval time_now __rte_cache_aligned;
	struct rte_mbuf *bufs[READER_BURST_SIZE] __rte_cache_aligned;

	struct param *param = (struct param *) arg;

	probe_context_t *probe_context __rte_cache_aligned = param->probe_context;
	struct rte_ring *ring __rte_cache_aligned = param->rx_ring;
	uint32_t next_stat_moment __rte_cache_aligned;
	const uint8_t input_port __rte_cache_aligned = atoi( probe_context->config->input->input_source );

	//redear should be run on lcore having the same socket with the on of its NIC
	if (rte_eth_dev_socket_id( input_port) > 0 &&
			rte_eth_dev_socket_id( input_port ) != rte_socket_id())
		log_write(LOG_WARNING, "Reader of port %u is on remote NUMA node to "
						"RX thread. Performance will not be optimal.",
						input_port );


	//next statistic moment in number of cycles
	gettimeofday(&time_now, NULL);
	next_stat_moment = time_now.tv_sec + probe_context->config->stat_period;

	const int queue_id = 0;

	uint64_t start_cycles = rte_get_tsc_cycles();
	/* Run until the application is quit or killed. */
	while ( likely( !probe_context->is_exiting )) {
			// Get burst of RX packets, from first port
			nb_rx = rte_eth_rx_burst( input_port, queue_id, bufs, READER_BURST_SIZE );

			//timestamp of a packet is the moment we retrieve it from buffer of DPDK
			//17 ns
			gettimeofday(&time_now, NULL);

			if( unlikely( time_now.tv_sec >= next_stat_moment )){
				_print_traffic_statistics( probe_context, &time_now );
				next_stat_moment += probe_context->config->stat_period;
			}

			if( unlikely( nb_rx == 0 )){
//				dpdk_pause( 200 );
			} else {
				//total received packets
				probe_context->traffic_stat.mmt.packets.receive += nb_rx;

				//for each received packet,
				// we remember the moment the packet is received
				for (i = 0; i < nb_rx; i++){
					struct timeval64 *t = ( struct timeval64 * )& bufs[i]->udata64;
					t->tv_sec = time_now.tv_sec;
					//suppose that each packet arrives after one microsecond
					t->tv_usec = time_now.tv_usec + i;

					//cumulate total data this reader received
					probe_context->traffic_stat.mmt.bytes.receive += bufs[i]->data_len;
				}

				unsigned sent = rte_ring_sp_enqueue_burst(ring, (void *)bufs, nb_rx, NULL);

				//ring is full
				if( unlikely( sent < nb_rx )){
					//cumulate total number of packets being dropped
					probe_context->traffic_stat.mmt.packets.drop += nb_rx - sent;

					while( sent < nb_rx ){
						//store number of bytes being dropped
						probe_context->traffic_stat.mmt.bytes.drop += bufs[ sent ]->data_len;

						//when a mbuf has not been sent, we need to free it
						rte_pktmbuf_free( bufs[sent ] );

						sent ++;
					}
				}
			}
	}

	log_write_dual(LOG_INFO, "Reader received %"PRIu64" pkt (%"PRIu64" B), dropped %"PRIu64" pkt (%6.3f %%), %"PRIu64" cpp",
			probe_context->traffic_stat.mmt.packets.receive,
			probe_context->traffic_stat.mmt.bytes.receive,
			probe_context->traffic_stat.mmt.packets.drop,
			(probe_context->traffic_stat.mmt.packets.receive == 0 ?
					0 : probe_context->traffic_stat.mmt.packets.drop *100.0 / probe_context->traffic_stat.mmt.packets.receive),
			(rte_get_tsc_cycles() - start_cycles )/probe_context->traffic_stat.mmt.packets.receive
	);

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
	uint16_t nb_workers = context->config->thread->thread_count;

	// Configure the Ethernet device: no tx
	int ret = rte_eth_dev_configure(input_port, nb_rx_queues, 0 , &port_default_conf);
	if( ret != 0 )
		rte_exit_failure( "Cannot configure port %d (%s)", input_port, rte_strerror(ret) );

	uint16_t nb_rxd = RX_DESCRIPTORS, nb_txd = 0;

	// Creates a new mempool in memory to hold the mbufs.
	snprintf( name, sizeof( name), "pool_%d", input_port );
	mbuf_pool = rte_pktmbuf_pool_create( name,

			+ nb_rx_queues*(nb_rxd*2)  //nic queue
			+ READER_QUEUE_SIZE * 2   //reader
			+ WORKER_QUEUE_SIZE * nb_workers    //distributor
			- 1,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket_id);

	if (mbuf_pool == NULL)
		rte_exit_failure( "Cannot create mbuf_pool for port %d", input_port );

	//update nb of descriptors
	ret = rte_eth_dev_adjust_nb_rx_tx_desc( input_port, &nb_rxd, &nb_txd);
	if (ret < 0)
		rte_exit_failure( "Cannot adjust number of descriptors for port=%d: %s",
				input_port, rte_strerror( ret ));
	else
		log_write( LOG_INFO, "Adjust number of rx descriptors of port %d to %d",
				input_port, nb_rxd );

	//init rx queue(s) of NIC
	int q;
	for( q=0; q<nb_rx_queues; q++ ){
		// Allocate and set up the first RX queue
		ret = rte_eth_rx_queue_setup( input_port,
				q,
				RX_DESCRIPTORS,
				socket_id,
				&rx_default_conf,
				mbuf_pool);

		if (ret < 0)
			rte_exit_failure( "Cannot init queue of port %d (%s)",
					input_port, rte_strerror(ret) );
	}

	//create a ring that is a buffer between reader and distributor:
	// reader ==> (ring) ===> distributor
	snprintf( name, sizeof( name), "ring_%d", input_port );
	//TODO: check context->config->thread->thread_queue_packet_threshold is power of 2
	param->rx_ring = rte_ring_create( name,
			READER_QUEUE_SIZE,
			socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);

	if ( param->rx_ring == NULL )
		rte_exit_failure( "Cannot init ring of port %d (%s). ",
				//"Either increase the hugepage size or decrease ring size."
				input_port, rte_strerror(ret) );

	//init distributor
	param->distributor = distributor_create( socket_id,
				//The maximum number of workers that will request packets from this distributor
				nb_workers,
				WORKER_QUEUE_SIZE
				);

	if( param->distributor == NULL)
		rte_exit_failure( "Cannot create distributor for port %d (%s)",
				input_port, rte_strerror(ret) );

	// Start the Ethernet port.
	ret = rte_eth_dev_start( input_port );

	if (ret < 0)
		rte_exit_failure("Cannot start port %d (%s)", input_port, rte_strerror( ret ) );

	// Enable RX in promiscuous mode for the Ethernet device.
	rte_eth_promiscuous_enable( input_port );
}

static inline void _dpdk_capture_release( probe_context_t *context ){
	int i;
	for( i=0; i<context->config->thread->thread_count; i++ )
		worker_release( context->smp[i] );
	mmt_probe_free( context->smp );
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
				"enough cores to run this application. It needs at least %d lcores",
				3 + context->config->thread->thread_count);

	// Initialize input port
	input_port = atoi( context->config->input->input_source );

	struct param param;
	param.distributor = NULL;
	param.rx_ring     = NULL;
	param.probe_context = context;
	_port_init(input_port, context, &param );

	context->smp = mmt_alloc( sizeof( worker_context_t ) * context->config->thread->thread_count );

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
		context->smp[i]->dpdk = mmt_alloc( sizeof( struct dpdk_worker_context_struct ));
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

	// Waiting for all workers finish their jobs

	//rte_eal_mp_wait_lcore();
	for( i=0; i< context->config->thread->thread_count; i++ )
		sem_wait( & context->smp[i]->dpdk->semaphore );

	//====> all workers have been stopped <====//

	//statistic of each worker
	worker_print_common_statistics( context );

	//statistic of DPDK
	_print_dpdk_stats( input_port );

	distributor_release( param.distributor );
	_dpdk_capture_release( context );
	fflush( stdout );
}


//#define _DPDK
void *_malloc( size_t size){
#ifdef _DPDK
	void *x = rte_malloc( NULL, size, 0 );
	if( x == NULL ){
		fprintf(stderr, "!!!ERROR: Not enough memory to allocate %zu bytes\n", size );
	}
	return x;
#else
	return malloc( size );
#endif
}

void _free( void *x ){
#ifdef _DPDK
	rte_free( x );
#else
	free( x );
#endif
}

void* _realloc( void *x, size_t size ){
#ifdef _DPDK
	x = rte_realloc(x, size, 0);
	if( x == NULL ){
		fprintf(stderr, "!!!ERROR: Not enough memory to reallocate %zu bytes\n", size );
	}
	return x;
#else
	return realloc( x, size );
#endif
}
