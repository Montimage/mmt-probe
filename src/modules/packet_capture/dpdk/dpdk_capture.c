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

#include "../../../worker.h"
#include "../../../lib/memory.h"

#define RX_DESCRIPTORS         4096  /* Size for RX ring*/
#define READER_BURST_SIZE        64  /* Burst size to receive packets from RX ring */
#define WORKER_BURST_SIZE        64
#define DISTRIBUTOR_BURST_SIZE  256
#define MBUF_CACHE_SIZE         512  //

//threshold to push pkt to distributor's ring
#define READER_DRAIN_PKT_THRESH   	 256
#define READER_DRAIN_CYCLE_THRESH 500000

#define DISTRIBUTOR_RING_SIZE  (4096 * 16)

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
	struct rte_ring *ring;
	sem_t semaphore;
}__rte_cache_aligned;

//input parameter of reader and distributor threads
struct param{
	struct rte_ring   *distributor_ring; //a ring between Reader --------> Distributor
	struct rte_ring  **worker_rings;     // rings between Distributor ===> Workers
	probe_context_t   *probe_context;
	uint8_t input_ports[ RTE_MAX_ETHPORTS ];
	uint8_t nb_ports;
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
				.wthresh = 4    /* Ring writeback threshold */
		},
		.rx_free_thresh = 0,    /* Immediately free RX descriptors */
		.rx_drop_en     = 1      /* Drop packets if no descriptors are available.*/
};

/* eth port configuration struct */
static const struct rte_eth_conf port_default_conf = {
		.rxmode = {
				.mq_mode        = ETH_MQ_RX_RSS,
//				.mq_mode        = ETH_MQ_RX_NONE,
				.max_rx_pkt_len = ETHER_MAX_LEN,
				.split_hdr_size = 0,
				.header_split   = 0, /**< Header Split disabled */
				.hw_ip_checksum = 0, /**< IP checksum offload disabled */
				.hw_vlan_filter = 0, /**< VLAN filtering disabled */
				.jumbo_frame    = 0, /**< Jumbo Frame Support disabled */
				.hw_strip_crc   = 0,
		},
		.rx_adv_conf = {
				.rss_conf = {
						.rss_key     = hash_key,
						.rss_key_len = 52,
						.rss_hf      = ETH_RSS_PROTO_MASK,
				},
		},
};


static inline void _pause( uint16_t cycles ){
	rte_pause();
	uint64_t t = rte_rdtsc() + cycles;

	while (rte_rdtsc() < t)
		rte_pause();
}


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

		log_write_dual( LOG_INFO, "NIC received %"PRIu64" packets, dropped %"PRIu64" (%.2f%%), error %"PRIu64" (%.2f%%), alloc failures %"PRIu64,
				total_pkt,
				stat.imissed,
				total_pkt == 0 ? 0 : (stat.imissed * 100.0 / total_pkt),
				stat.ierrors,
				total_pkt == 0 ? 0 : (stat.ierrors * 100.0 / total_pkt ),
				stat.rx_nombuf
		);
	}
}


static int _worker_thread( void *arg ){
	worker_context_t *worker_context = (worker_context_t *)arg;
	const probe_conf_t *config       = worker_context->probe_context->config;
	struct rte_ring *ring            = worker_context->dpdk->ring;
	int i;
	struct pkthdr pkt_header __rte_cache_aligned;
	const u_char* pkt_data;

	worker_on_start( worker_context );

	pkt_header.user_args = NULL;

	//The mbufs pointer array to be filled in (up to 8 packets)
	struct rte_mbuf *packets[ WORKER_BURST_SIZE ] __rte_cache_aligned;

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
		unsigned nb_rx = rte_ring_sc_dequeue_burst(ring, (void *)packets, WORKER_BURST_SIZE, NULL );

		if( unlikely( nb_rx == 0 )){
			_pause( 2000 );
		}else {

			//last packet is special one to tell worker exist
			if( unlikely( packets[ nb_rx - 1 ] == NULL)){
				is_continuous = false;
				nb_rx --;
			}

			rte_prefetch_non_temporal((void *)packets[0]);
			rte_prefetch_non_temporal((void *)packets[1]);
			rte_prefetch_non_temporal((void *)packets[2]);

			for (i = 0; i < nb_rx; i++){
				//prefetch
				rte_prefetch_non_temporal((void *)packets[ i + 3 ]);

				pkt_header.len         = packets[i]->pkt_len;
				pkt_header.caplen      = packets[i]->data_len;
				//decode timestamp
				struct timeval64 *t   = (struct timeval64 *) & packets[i]->udata64;
				pkt_header.ts.tv_sec  = t->tv_sec;
				pkt_header.ts.tv_usec = t->tv_usec;

				//get packet data
				pkt_data = (packets[i]->buf_addr + packets[i]->data_off);

				//process packet
				worker_process_a_packet( worker_context, &pkt_header, pkt_data );

				//TODO: this is to test only
				//do a small processing
//				_pause( 1000 );

				//after processing packet, we need to free its memory in mempool
				// to have place for others coming
				rte_pktmbuf_free( packets[i] );
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


static inline void _print_traffic_statistics( probe_context_t *context, const struct timeval *now, uint8_t *input_ports, uint8_t nb_ports ){
	struct rte_eth_stats stat;
	int i;
	uint8_t input_port;
	for( i=0; i<nb_ports; i++ ){
		input_port = input_ports[ i ];
		rte_eth_stats_get( input_port, &stat );

		context->traffic_stat.nic.drop    = stat.imissed + stat.ierrors;
		context->traffic_stat.nic.receive = stat.ipackets + stat.imissed + stat.ierrors;
	}
	context_print_traffic_stat( context, now );

//	char *name = "pool_0";
//	struct rte_mempool *mempool = rte_mempool_lookup(name);
//	printf("-pool free: %d / %d\n", rte_mempool_avail_count( mempool ), mempool->size );

//	struct rte_malloc_socket_stats mem_stats;
//	rte_malloc_get_socket_stats( port, &mem_stats);
//	printf("memory:\n\t- heap %zu\n\t- allocated %zu bytes (%zu)\n\t- free %zu bytes (%zu)\n",
//			mem_stats.heap_totalsz_bytes,
//			mem_stats.heap_allocsz_bytes, mem_stats.alloc_count,
//			mem_stats.heap_freesz_bytes,  mem_stats.free_count);
}

static int _distributor_thread( void *arg ){
	int i;
	volatile bool is_continuous = true;
	struct rte_mbuf *packets[DISTRIBUTOR_BURST_SIZE];

	struct param *param = (struct param *) arg;

	struct rte_ring *ring  = param->distributor_ring;
	struct rte_ring **worker_rings = param->worker_rings;
	probe_context_t *probe_context __rte_cache_aligned = param->probe_context;
	const uint16_t nb_workers = probe_context->config->thread->thread_count;

	struct timeval time_now __rte_cache_aligned;
	uint32_t next_stat_moment __rte_cache_aligned;

	struct buffer{
		uint64_t size;
		struct rte_mbuf *packets[DISTRIBUTOR_BURST_SIZE]  __rte_cache_aligned;
	} *buffers;

	//next statistic moment in number of cycles
	gettimeofday(&time_now, NULL);
	next_stat_moment = time_now.tv_sec + probe_context->config->stat_period;

	//statistic variables
	size_t total_bytes_dropped = 0, total_pkt_dropped = 0;

	//local buffers to store packets before inserting by burst to workers' rings
	buffers = rte_zmalloc("worker buffers", sizeof( struct buffer ) * nb_workers, RTE_CACHE_LINE_SIZE );

	uint8_t target_worker_id;

	const uint64_t start_cycles = rte_rdtsc();

	/* Run until the distributor received a null packet. */
	while ( likely( is_continuous )) {
		unsigned nb_rx = rte_ring_sc_dequeue_burst( ring, (void *)packets, DISTRIBUTOR_BURST_SIZE, NULL );

		//timestamp of a packet is the moment we retrieve it from buffer of DPDK
		//on Intel® Xeon® Processor E5-2699 v4 (55M Cache, 2.20 GHz), this function takes ~17 ns
		gettimeofday( &time_now, NULL );

		//periodically do a statistic of received/dropped packets
		if( unlikely( time_now.tv_sec >= next_stat_moment )){

			_print_traffic_statistics( probe_context, &time_now, param->input_ports, param->nb_ports );

			next_stat_moment += probe_context->config->stat_period;
		}

		if( unlikely( nb_rx == 0 )){
			//we need a small pause here -> reader_thread can easily to insert packet to queue
			//at 14Mpps -> 1 packet consumes ~215 cycles (~67 ns)
			//=> sleep 20 packets
			_pause( 6000 );
		} else {

			//received a null message at the end => exit
			if( unlikely( packets[ nb_rx - 1 ] == NULL )){
				nb_rx --;
				is_continuous = false; //exit while loop
			}

			//total received packets
			probe_context->traffic_stat.mmt.packets.receive += nb_rx;

			//TODO: this block is for testing only
//			{
//			for (i = 0; i < nb_rx; i++)
//				rte_pktmbuf_free( packets[ i ] );
//			nb_rx = 0;
//			}


			//for each received packet,
			for (i = 0; i < nb_rx; i++){
				// we remember the moment the packet is received
				struct timeval64 *t = ( struct timeval64 * )& packets[i]->udata64;
				t->tv_sec = time_now.tv_sec;
				//suppose that each packet arrives after one microsecond
				t->tv_usec = time_now.tv_usec + i;

				//cumulate total data this reader received
				probe_context->traffic_stat.mmt.bytes.receive += packets[i]->data_len;

				//distribute packet to a worker
				target_worker_id = packets[i]->hash.usr % nb_workers;
//				By selecting nb_workers to be a power of two, the modulo operator can be replaced by a bitwise AND logical operation:
//				target_worker_id = packets[i]->hash.usr & (nb_workers - 1);

				//put the packet into the worker's buffer that will be then enqueued by burst to the worker's ring
				buffers[ target_worker_id ].packets[  buffers[ target_worker_id ].size ++  ] = packets[i];
			}

			//push buffers to workers by enqueueing them into workers' rings
			for( i=0; i<nb_workers; i++ ){
				unsigned nb_pkts = buffers[i].size;

				//no packets for this worker
				if( unlikely( nb_pkts  == 0 ))
					continue;

				unsigned sent = rte_ring_sp_enqueue_burst( worker_rings[i], (void *) buffers[i].packets, nb_pkts, NULL );

				//worker's ring is full ??
				if( unlikely( sent < nb_pkts )){
					//cumulate total number of packets being dropped
					size_t pkt_dropped  = nb_pkts - sent;
					size_t bytes_dropped = 0;

					while( sent < nb_pkts ){
						//store number of bytes being dropped
						bytes_dropped += buffers[i].packets[ sent ]->data_len;

						//when a mbuf has not been sent, we need to free it
						rte_pktmbuf_free( buffers[i].packets[sent ] );

						sent ++;
					}

					//update stats
					probe_context->smp[i]->stat.pkt_dropped      += pkt_dropped;
					probe_context->traffic_stat.mmt.packets.drop += pkt_dropped;
					probe_context->traffic_stat.mmt.bytes.drop   += bytes_dropped;
				}

				//reset buffer
				buffers[ i ].size = 0;
			}
		}
	}

	size_t cycle_proc = rte_rdtsc() - start_cycles ;
	size_t pkt_proc = probe_context->traffic_stat.mmt.packets.receive - probe_context->traffic_stat.mmt.packets.drop;

	log_write_dual(LOG_INFO, "MMT worker processes totally received %"PRIu64" pkts (%"PRIu64" B), dropped %"PRIu64" pkt (%6.3f %%), %"PRIu64" cpp (proc: %"PRIu64" )",
			probe_context->traffic_stat.mmt.packets.receive,
			probe_context->traffic_stat.mmt.bytes.receive,
			probe_context->traffic_stat.mmt.packets.drop,
			(probe_context->traffic_stat.mmt.packets.receive == 0 ?
					0 : probe_context->traffic_stat.mmt.packets.drop *100.0 / probe_context->traffic_stat.mmt.packets.receive),
			(probe_context->traffic_stat.mmt.packets.receive == 0 ?
					0 : cycle_proc/probe_context->traffic_stat.mmt.packets.receive),
			(pkt_proc == 0 ? 0 : cycle_proc / pkt_proc )
	);


	//send a NULL packet to all workers to tell them to exit
	for( i=0; i<nb_workers; i++)
		//ensure the packet is sent to its worker
		while( rte_ring_sp_enqueue( worker_rings[i], NULL ) ){
			_pause( 1000 );
		}

	rte_free( buffers );

	return 0;
}


/**
 * This is Reader thread.
 * It receives packets from NIC then forward them to Distributer
 */
static int _reader_thread( void *arg ){
	struct rte_mbuf *packets_buf[ READER_BURST_SIZE + READER_DRAIN_PKT_THRESH ] __rte_cache_aligned;

	struct param *param = (struct param *) arg;
	probe_context_t *probe_context = param->probe_context;
	struct rte_ring *ring = param->distributor_ring;
	uint8_t input_port;
	int i;
	for( i=0; i<param->nb_ports; i++ ){
		input_port = param->input_ports[i];

		//reader needs to run on lcore having the same socket with the one of its NIC
		if (rte_eth_dev_socket_id( input_port) > 0 &&
				rte_eth_dev_socket_id( input_port ) != rte_socket_id())
			log_write(LOG_WARNING, "Reader of port %u is on remote NUMA node to "
					"RX thread. Performance will not be optimal.",
					input_port );
	}
	const int queue_id = 0;
	size_t nb_enqueue_failures = 0;
	size_t nb_full_nic = 0; //number of times we get full READER_BURST_SIZE
	size_t total_bytes_dropped = 0, total_pkt_dropped = 0;

	size_t total_pkt_received = 0, total_cycles = 0;;

	uint16_t nb_rx = 0;

	size_t next_drain_moment = rte_rdtsc() + READER_DRAIN_CYCLE_THRESH;

	/* Run until the application is quit or killed. */
	while ( likely( !probe_context->is_exiting )) {
		//round-robin through each input port
		for( i=0; i<param->nb_ports; i++ ){
			input_port = param->input_ports[i];

			// Get burst of RX packets from port
			nb_rx += rte_eth_rx_burst( input_port, queue_id, packets_buf + nb_rx, READER_BURST_SIZE );

			if( unlikely( nb_rx == 0 )){
				continue;
			} else {
				if( nb_rx == READER_BURST_SIZE )
					nb_full_nic ++;

				if( nb_rx >= READER_DRAIN_PKT_THRESH || rte_rdtsc() >= next_drain_moment ){

					unsigned sent = rte_ring_sp_enqueue_bulk(ring, (void *)packets_buf, nb_rx, NULL);

					//ring is full
					if( unlikely( sent < nb_rx )){
						nb_enqueue_failures ++;
						//cumulate total number of packets being dropped
						total_pkt_dropped += nb_rx - sent;

						do{
							//store number of bytes being dropped
							total_bytes_dropped += packets_buf[ sent ]->data_len;

							//when a mbuf has not been sent, we need to free it
							rte_pktmbuf_free( packets_buf[sent ] );

							sent ++;
						}while( sent < nb_rx );
					}


					total_pkt_received += nb_rx;

					//reset param
					nb_rx = 0;
					next_drain_moment += READER_DRAIN_CYCLE_THRESH;
				}
			}
		}
	}


	//statistic of DPDK
	for( i=0; i<param->nb_ports; i++ ){
		input_port = param->input_ports[i];
		_print_dpdk_stats( input_port );
	}

	log_write_dual( LOG_INFO, "MMT reader process received %zu pkts, dropped %zu pkts (%.2f%% = %zu bytes), %zu full-nic, %zu full-dis-ring",
			total_pkt_received,
			total_pkt_dropped,
			total_pkt_dropped * 100.0 / total_pkt_received,
			total_bytes_dropped,
			nb_full_nic,
			nb_enqueue_failures );


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
static inline void _port_init( int input_port, probe_context_t *context, struct param *param, bool is_init_worker_rings ){
	int i;
	struct rte_mempool *mbuf_pool;
	char name[100];
	unsigned socket_id = rte_eth_dev_socket_id( input_port );
	const uint16_t nb_rx_queues = 1; //context->config->thread->thread_count
	const uint16_t nb_workers = context->config->thread->thread_count;
	const uint32_t worker_ring_size = context->config->thread->thread_queue_packet_threshold;

	if( ! is_power_of_two( worker_ring_size) )
		rte_exit_failure("Unexpected thread-queue=%d. Must be a power of 2", worker_ring_size );

	// Configure the Ethernet device: no tx
	int ret = rte_eth_dev_configure(input_port, nb_rx_queues, 0 , &port_default_conf);
	if( ret != 0 )
		rte_exit_failure( "Cannot configure port %d (%s)", input_port, rte_strerror(ret) );

	uint16_t nb_rx_descriptors = RX_DESCRIPTORS, nb_txd = 0;

	//update nb of descriptors
	ret = rte_eth_dev_adjust_nb_rx_tx_desc( input_port, &nb_rx_descriptors, &nb_txd);
	if (ret < 0)
		rte_exit_failure( "Cannot adjust number of descriptors for port=%d: %s",
				input_port, rte_strerror( ret ));
	else
		log_write( LOG_INFO, "Adjust number of rx descriptors of port %d to %d",
				input_port, nb_rx_descriptors );

	//number of elements in mempool should be 2^n-1
	unsigned nb_pktmbuf =
			  nb_rx_queues*RX_DESCRIPTORS                         //nic queue
			+ READER_BURST_SIZE + READER_DRAIN_PKT_THRESH         //reader
			+ DISTRIBUTOR_RING_SIZE + DISTRIBUTOR_BURST_SIZE      //distributor
			+ (worker_ring_size + WORKER_BURST_SIZE) * nb_workers //workers
	;
	//get the next power of 2
	unsigned val = 1;
	while( val <= nb_pktmbuf )
		val *= 2;
	//optimal number : 2^n-1
	nb_pktmbuf = val - 1;

	log_write( LOG_INFO, "Set a mempool containing %u packets, cach size: %d", nb_pktmbuf, MBUF_CACHE_SIZE );

	// Creates a new mempool in memory to hold a set of mbuf objects
	// that will be used by the driver and the application to store network packet data
	snprintf( name, sizeof( name), "pool_%d", input_port );
	mbuf_pool = rte_pktmbuf_pool_create( name,
			nb_pktmbuf,
			MBUF_CACHE_SIZE,
			0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			socket_id);

	if (mbuf_pool == NULL)
		rte_exit_failure( "Cannot create mbuf_pool for port %d", input_port );

	//init rx queue(s) of NIC
	int queue_id;
	for( queue_id=0; queue_id<nb_rx_queues; queue_id++ ){
		// Allocate and set up the first RX queue
		ret = rte_eth_rx_queue_setup( input_port,
				queue_id,
				nb_rx_descriptors,
				socket_id,
				&rx_default_conf,
				mbuf_pool);

		if (ret < 0)
			rte_exit_failure( "Cannot initialize queue %d of port %d (%s)",
					queue_id, input_port, rte_strerror(ret) );
	}

	if( is_init_worker_rings ){
		//create a ring that is a buffer between reader and distributor:
		// reader ==> (ring) ===> distributor
		param->distributor_ring = rte_ring_create( "distributor",
				DISTRIBUTOR_RING_SIZE,
				socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);

		if ( param->distributor_ring == NULL )
			rte_exit_failure( "Cannot initialize distributor");

		//init worker rings: distributor ===> (rings) ===> workers
		param->worker_rings = rte_malloc( "worker_rings", sizeof( struct rte_ring *) * nb_workers, RTE_CACHE_LINE_SIZE );
		if( param->worker_rings == NULL )
			rte_exit_failure("Cannot allocate memory for worker rings");

		//
		for( i=0; i<nb_workers; i++ ){
			snprintf( name, sizeof( name), "worker_ring_%d", i );

			param->worker_rings[i] = rte_ring_create( name,
					worker_ring_size,
					socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);

			if( param->worker_rings[i] == NULL )
				rte_exit_failure("Cannot allocate memory for worker ring %d", i);
		}
	}

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

//	unsigned x = -1;
//	printf("sizeof(unsigned)=%d, max=%u\n", sizeof( x ), x ); //==> sizeof(unsigned)=4, max=4294967295

	//we need at least:
	// - one core for main thread
	// - one core for reader
	// - one core for distributor, and
	// - n cores for workers
	if ( total_of_cores < 3 + context->config->thread->thread_count )
		rte_exit_failure( "This application does not have "
				"enough cores to run this application. It needs at least %d lcores",
				3 + context->config->thread->thread_count);

	struct param param;
	//initialize param that is shared among Reader -and- Distributor
	param.probe_context = context;

	char *arr[ RTE_MAX_ETHPORTS ];
	param.nb_ports = string_split( context->config->input->input_source, ",", arr, RTE_MAX_ETHPORTS );
	for( i=0; i<param.nb_ports; i++ ){
		// Initialize input port
		param.input_ports[i] = atoi( arr[i] );

		_port_init(param.input_ports[i], context, &param, i == 0 );
	}

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
		context->smp[i]->dpdk->ring = param.worker_rings[i];

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


	_dpdk_capture_release( context );
	fflush( stdout );

	//close ports
	for( i=0; i<param.nb_ports; i++ ){
		input_port = param.input_ports[i];

		rte_eth_dev_stop( input_port );
		rte_eth_dev_close( input_port );
	}
}
