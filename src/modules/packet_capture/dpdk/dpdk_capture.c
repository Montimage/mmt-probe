/*
 * dpdk_capture.c
 *
 *  Created on: Dec 20, 2016
 *      Author: montimage
 *
 * We use:
 * - A NIC has "n" queues corresponding "n" workers
 * - "m" Readers.
 * Each Reader reads traffic from n/m queues and distributes packets to the private queue of the corresponding worker
 * Each Worker reads packets form its queue, process packets, and output statistic information
 *
 *    [ RX queue ]      ________       => [ Worker ]
 *    [ RX queue ]     |        |    ||=> [ Worker ]
 *    [ RX queue ] ===>| Reader | ======> [ Worker ]
 *    [ RX queue ]     |________|      => [ Worker ]
 * NIC                  ________
 *    [ RX queue ]     |        |    ||=> [ Worker ]
 *    [ RX queue ] ===>| Reader | ======> [ Worker ]
 *    [ RX queue ]     |________|    ||=> [ Worker ]
 *    [ RX queue ]                     => [ Worker ]
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
#include <time.h>

#include "dpdk_capture.h"

#include "../../../worker.h"
#include "../../../lib/memory.h"

#define NB_READERS_PER_PORT         2  // 2 readers
#define RX_DESCRIPTORS           4096  // Number of RX descriptors of a NIC queue

#define READER_BURST_SIZE          32  /* Burst size to receive packets from RX ring */
#define READER_DRAIN_THRESH   	  256  ////threshold to push pkt to distributor's ring

#define WORKER_BURST_SIZE          64

#define MBUF_CACHE_SIZE           256  // Number of mbuf on cache


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

struct _stat{
	rte_atomic64_t packets;
	rte_atomic64_t bytes;
};

//input parameter of reader
struct reader_param{
	struct rte_ring  **worker_rings;     // rings of Workers
	struct _stat stat_received;
	struct _stat stat_dropped;

	uint64_t *pkts_dropped; //detail no pkts dropped when they cannot be inserted to workers' rings

	uint8_t nb_workers;
	uint8_t input_port;
	uint8_t reader_id;

	sem_t semaphore;
}__rte_cache_aligned;



/* RX configuration struct */
static const struct rte_eth_rxconf rx_default_conf = {
		.rx_thresh = {
				.pthresh = 8,   /* Ring prefetch threshold */
				.hthresh = 8,   /* Ring host threshold */
				.wthresh = 4    /* Ring writeback threshold */
		},
		.rx_free_thresh = 4,    /* free RX descriptors */
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


struct timeval64{
	union{
		uint64_t val;
		struct{
			uint32_t tv_sec;
			uint32_t tv_nsec;
		};
	};
};

/**
 * Encode a timeval to a number of 8bytes
 */
static inline uint64_t _time_to_uint64( const struct timespec *time ){
	//uint64_t val = (time->tv_usec & 0xFFFFFFFF) | ( (uint64_t)time->tv_sec << 32 );
	//return val;
	struct timeval64 t;
	t.tv_sec  = time->tv_sec;
	t.tv_nsec = time->tv_nsec;
	return t.val;
}

/**
 * Decode a number of 8bytes to a timeval
 */
static inline void _uint64_to_timeval( struct timeval *time, uint64_t val ){
	//time->tv_sec  = val >> 32;
	//time->tv_usec = val & 0xFFFFFFFF;
	struct timeval64 t;
	t.val = val;
	time->tv_sec  = t.tv_sec;
	time->tv_usec = t.tv_nsec / 1000;

//	if( time->tv_sec == 0 && time->tv_usec == 0 )
//		printf(".");
}

/**
 * Get the 4 highest bytes from a number of 8bytes
 */
static inline uint32_t _tv_sec_from_uint64( uint64_t val ){
	//return (val >> 32);
	struct timeval64 t;
	t.val = val;
	return t.tv_sec;
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

		log_write_dual( LOG_INFO, "NIC port %d received %"PRIu64" packets, dropped %"PRIu64" (%.2f%%), error %"PRIu64" (%.2f%%), alloc failures %"PRIu64,
				port_number,
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


	struct timeval now; //current timestamp that is
	// real timestamp of system because this is running online

	volatile bool is_continuous = true;
	/* Run until the application is quit or killed. */
	while ( likely( is_continuous )) {
		// Get burst of RX packets, from first port
		unsigned nb_rx = rte_ring_sc_dequeue_burst(ring, (void *)packets, WORKER_BURST_SIZE, NULL );

		if( unlikely( nb_rx == 0 )){
			//we need a small pause here -> reader_thread can easily to insert packet to queue
			//at 14Mpps -> 1 packet consumes ~67 ns (~67*2.2 cycles) (CPU 2.2Ghz)
			//=> sleep 35 packets
			//_pause( 35*2.2*67 );
			_pause( 5000 );
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
				//prefetch in advance 3 elements
				rte_prefetch_non_temporal((void *)packets[ i + 3 ]);

				pkt_header.len         = packets[i]->pkt_len;
				pkt_header.caplen      = packets[i]->data_len;
				//decode timestamp
				_uint64_to_timeval( & pkt_header.ts, packets[i]->udata64 );

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
		gettimeofday( & now, NULL );
		worker_update_timer( worker_context, now );
	}

	worker_on_stop( worker_context );

	//finish, wake up the main thread
	sem_post( &worker_context->dpdk->semaphore );

	return 0;
}


static volatile bool is_continuous = true;

static int _reader_thread( void *arg ){
	int i;
	struct reader_param *param = (struct reader_param *) arg;

	struct rte_ring **worker_rings = param->worker_rings;
	const uint16_t nb_workers      = param->nb_workers;

	const uint8_t input_port = param->input_port;
	const uint8_t input_queue_begin = param->reader_id * nb_workers;

	//struct timeval time_now __rte_cache_aligned; //to get the current timestamp
	struct timespec time_now __rte_cache_aligned; //to get the current timestamp

	struct buffer{
		uint32_t packets_count;
		uint32_t bytes_count;
		struct rte_mbuf *packets[READER_DRAIN_THRESH + READER_BURST_SIZE];

		//they are for statistic: number of packets and bytes the reader
		// cannot enqueue to worker's ring
		uint32_t packets_dropped;
		uint32_t bytes_dropped;
	} *buffers;


	uint64_t nb_full_nic = 0;

	//reader needs to run on lcore having the same socket with the one of its NIC
	if (rte_eth_dev_socket_id( input_port) > 0 &&
			rte_eth_dev_socket_id( input_port ) != rte_socket_id())
		log_write(LOG_WARNING, "Reader of port %u is on remote NUMA node to "
				"RX thread. Performance will not be optimal.",
				input_port );

	//local buffers to store packets before inserting by burst to workers' rings
	buffers = rte_zmalloc("worker buffers", sizeof( struct buffer ) * nb_workers, RTE_CACHE_LINE_SIZE );

	uint16_t worker_id;
	const uint64_t start_cycles = rte_rdtsc();


	/* Run until the distributor received a null packet. */
	while ( likely( is_continuous )) {

		//timestamp of a packet is the moment we retrieve it from buffer of DPDK
		//on Intel® Xeon® Processor E5-2699 v4 (55M Cache, 2.20 GHz),
		// this function takes ~27 ns ( ~ 27*2.2 = 60 cycles)
		//see: test/perf/gettimeofday.c
		//gettimeofday( &time_now, NULL );

		//faster: 8 ns
		clock_gettime( CLOCK_REALTIME_COARSE, &time_now );

		//for each worker (and also each input queue)
		for( worker_id=0; worker_id<nb_workers; worker_id++ ){
			uint16_t input_queue = input_queue_begin + worker_id;

			//take the available part
			struct rte_mbuf **packets = buffers[worker_id].packets  + buffers[worker_id].packets_count;

			//receive packets from RX queue and append them to buffer of worker
			unsigned nb_rx = rte_eth_rx_burst( input_port,
					input_queue,
					packets,
					READER_BURST_SIZE );

			if( unlikely( nb_rx == 0 )){
				continue;
			} else {

				if( unlikely( nb_rx == READER_BURST_SIZE ))
					nb_full_nic ++;

				//increase the number of packets in a buffer of i-th worker
				buffers[worker_id].packets_count += nb_rx;

				//remember the moment received packets
				for (i = 0; i < nb_rx; i++){
					// we remember the moment the packet is received
					packets[i]->udata64 = _time_to_uint64( &time_now );

					//suppose that each packet arrives after one microsecond
					//time_now.tv_usec ++;

					//cumulate total data this reader received
					buffers[worker_id].bytes_count += packets[i]->data_len;
				}


				//total number of packets are in buffer of i-th worker
				unsigned nb_pkts = buffers[worker_id].packets_count;
				//timestamp of the first packet in the buffer of worker_id
				uint32_t timestamp_of_first_packet = _tv_sec_from_uint64( buffers[worker_id].packets[0]->udata64 );

				//for each worker, we flush the buffer to its ring when
				// - either the buffer size >= READER_DRAIN_THRESH
				// - or each one second
				if( nb_pkts >= READER_DRAIN_THRESH
						//when interval between the first packet and now >= 1 second
						// => drain each second
						|| time_now.tv_sec > timestamp_of_first_packet ){


					uint64_t pkt_dropped = 0, bytes_dropped = 0;
					//push buffers to workers by enqueueing them into workers' rings
					unsigned sent = rte_ring_sp_enqueue_burst( worker_rings[worker_id],
							(void *) buffers[worker_id].packets, nb_pkts, NULL );

					//worker's ring is full ??
					//=> we need to free the packets that has not been enqueued
					if( unlikely( sent < nb_pkts )){
						//give another try
						// since this operation may be fall by occurs of some interrupt
						sent += rte_ring_sp_enqueue_burst( worker_rings[worker_id],
									(void *) buffers[worker_id].packets + sent, nb_pkts - sent, NULL );

						//ok, now we can conclude that we cannot insert as the worker's ring is full
						if( unlikely( sent < nb_pkts )){
							//cumulate total number of packets being dropped
							pkt_dropped += nb_pkts - sent;

							do{
								//store number of bytes being dropped
								bytes_dropped += buffers[worker_id].packets[ sent ]->data_len;

								//when a mbuf has not been sent, we need to free it
								rte_pktmbuf_free( buffers[worker_id].packets[ sent ] );

								sent ++;
							}while( sent < nb_pkts );

							//update stats about dropped packets and bytes
							rte_atomic64_add( & param->stat_dropped.packets,  pkt_dropped );
							rte_atomic64_add( & param->stat_dropped.bytes,    bytes_dropped );

							//update number of packets being dropped by this worker
							//probe_context->smp[i]->stat.pkt_dropped += pkt_dropped;
							param->pkts_dropped[ worker_id ] += pkt_dropped;
						}
					}

					//total received packets
					rte_atomic64_add( & param->stat_received.packets, nb_pkts );
					rte_atomic64_add( & param->stat_received.bytes,   buffers[ worker_id ].bytes_count );

					//reset buffer
					buffers[worker_id].packets_count = 0;
					buffers[worker_id].bytes_count   = 0;
				}
			}
		}
	}

	size_t cycle_proc = rte_rdtsc() - start_cycles ;


	uint64_t packets_received = rte_atomic64_read( & param->stat_received.packets );
	uint64_t bytes_received   = rte_atomic64_read( & param->stat_received.bytes );
	uint64_t packets_dropped  = rte_atomic64_read( & param->stat_dropped.packets );
	size_t packets_proccessed = packets_received - packets_dropped;



	log_write_dual(LOG_INFO, "Reader %d of port %d processes totally received %"PRIu64" pkts (%"PRIu64" B), dropped %"PRIu64" pkt (%6.3f %%), %"PRIu64" cpp (proc: %"PRIu64" ), nic-full: %"PRIu64,
			param->reader_id,
			input_port,
			packets_received,
			bytes_received,
			packets_dropped,
			PERCENTAGE( packets_dropped, packets_received ),
			(packets_received == 0 ?
					0 : cycle_proc/packets_received),
			(packets_proccessed == 0 ? 0 : cycle_proc / packets_proccessed ),
			nb_full_nic
	);


	//send a NULL packet to all workers to tell them to exit
	for( i=0; i<nb_workers; i++)
		//ensure the packet is sent to its worker
		while( rte_ring_sp_enqueue( worker_rings[i], NULL ) ){
			_pause( 1000 );
		}

	rte_free( buffers );

	//finish, wake up the main thread
	sem_post( &param->semaphore );

	return 0;
}


/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline void _port_init( int input_port, probe_context_t *context, uint16_t nb_workers, struct reader_param *param ){
	int i;
	char name[100];
	unsigned socket_id = rte_eth_dev_socket_id( input_port );
	const uint32_t worker_ring_size = context->config->thread->thread_queue_packet_threshold;
	const uint16_t nb_rx_queues = nb_workers;
	//number of workers of a reader
	const uint8_t nb_workers_per_reader = nb_workers / NB_READERS_PER_PORT;
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

	//for each reader
	int reader_id;
	for( reader_id=0; reader_id < NB_READERS_PER_PORT; reader_id ++ ){
		//number of elements in mempool should be 2^n-1
		unsigned nb_pktmbuf =
				nb_workers_per_reader * RX_DESCRIPTORS                //nic queue
				+ READER_BURST_SIZE + READER_DRAIN_THRESH             //reader
				+ (worker_ring_size + WORKER_BURST_SIZE) * nb_workers_per_reader //workers
		;

		//get the next power of 2
		//unsigned val = 1;
		//while( val <= nb_pktmbuf )
		//	val *= 2;
		//optimal number : 2^n-1
		//nb_pktmbuf = val - 1;
		nb_pktmbuf += 10;

		log_write( LOG_INFO, "Set a mempool for queue %d of port %d containing %u packets, cach size: %d",
				reader_id, input_port,
				nb_pktmbuf, MBUF_CACHE_SIZE );


		// Creates a new mempool in memory to hold a set of mbuf objects
		// that will be used by the driver and the application to store network packet data
		snprintf( name, sizeof( name), "pool_%d_%d", input_port, reader_id );
		struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create( name,
				nb_pktmbuf,
				MBUF_CACHE_SIZE,
				0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
				socket_id);

		if (mbuf_pool == NULL)
			rte_exit_failure( "Cannot create mbuf_pool for queue %d of port %d", reader_id, input_port );

		//init worker rings: reader ===> (rings) ===> workers
		struct rte_ring **worker_rings = rte_malloc( "worker_rings", sizeof( struct rte_ring *) * nb_workers_per_reader, RTE_CACHE_LINE_SIZE );
		if( worker_rings == NULL )
			rte_exit_failure("Cannot allocate memory for worker rings");

		//each
		for( i=0; i<nb_workers_per_reader; i++ ){
			//each reader will process `nb_workers_per_reader` of queues
			uint16_t input_queue = nb_workers_per_reader * reader_id + i;

			// Allocate and set up the first RX queue
			ret = rte_eth_rx_queue_setup( input_port,
					input_queue,
					nb_rx_descriptors,
					socket_id,
					&rx_default_conf,
					mbuf_pool);

			if (ret < 0)
				rte_exit_failure( "Cannot initialize queue %d of port %d (%s)",
						input_queue, input_port, rte_strerror(ret) );


			//create worker's ring
			snprintf( name, sizeof( name), "worker_%d_%d_%d", input_port, reader_id, i );

			worker_rings[i] = rte_ring_create( name,
					worker_ring_size,
					socket_id, RING_F_SC_DEQ | RING_F_SP_ENQ);

			if( worker_rings[i] == NULL )
				rte_exit_failure("Cannot allocate memory for worker ring %d for reader %d of port %d",
						i, reader_id, input_port);
		}


		//
		param[reader_id].reader_id    = reader_id;
		param[reader_id].input_port   = input_port;
		param[reader_id].nb_workers   = nb_workers_per_reader;
		param[reader_id].worker_rings = worker_rings;

		rte_atomic64_init( & param[reader_id].stat_received.packets );
		rte_atomic64_init( & param[reader_id].stat_received.bytes );
		rte_atomic64_init( & param[reader_id].stat_dropped.packets );
		rte_atomic64_init( & param[reader_id].stat_dropped.bytes );
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
	char name[100];
	const unsigned total_of_cores   = rte_lcore_count();
	const uint16_t total_nb_workers = context->config->thread->thread_count;
	int i, ret;

	//check size of
	if( sizeof( struct timeval64 ) != sizeof( uint64_t ) ){
		rte_exit_failure("The system does not support encapsulate timeval to uint64_t");
	}

	char *input_port_names[ RTE_MAX_ETHPORTS ];
	const unsigned nb_ports = string_split( context->config->input->input_source, ",", input_port_names, RTE_MAX_ETHPORTS );

	if( total_nb_workers % ( nb_ports * NB_READERS_PER_PORT ) != 0 )
		rte_exit_failure("Number of workers (%d) must divide by number of ports and queues (%d)",
				total_nb_workers, ( nb_ports * NB_READERS_PER_PORT ) );

	if(  total_nb_workers == 0 )
		rte_exit_failure("Number of threads must be greater than 0");

	uint8_t input_ports[ RTE_MAX_ETHPORTS ];
	for( i=0; i<nb_ports; i++ )
		input_ports[i] = atoi( input_port_names[i] );


	//we need at least:
	// - one core for main thread
	// - m cores for each input port:
	// - n cores for workers
	const int need_of_cores = 1 + (nb_ports * NB_READERS_PER_PORT) + context->config->thread->thread_count;
	if ( total_of_cores < need_of_cores )
		rte_exit_failure( "This application does not have "
				"enough cores to run this application. It needs at least %d lcores",
				need_of_cores);

	struct reader_param reader_context[ RTE_MAX_ETHPORTS ][ NB_READERS_PER_PORT ];
	const uint8_t nb_workers_per_port = total_nb_workers / nb_ports;
	context->smp = mmt_alloc( sizeof( worker_context_t *) *  total_nb_workers);

	int lcore_id  = 0;
	int worker_id = 0;

	//Iteration variables
	int port_index, reader_index, worker_index;

	//for each input port
	for( port_index=0; port_index<nb_ports; port_index++ ){
		int input_port = input_ports[port_index];

		struct reader_param *p = reader_context[port_index];
		// Initialize input port
		_port_init( input_port, context, nb_workers_per_port, p );

		//for each queue of a port
		for( reader_index=0; reader_index < NB_READERS_PER_PORT; reader_index ++ ){

			for( worker_index=0; worker_index < p[reader_index].nb_workers; worker_index++ ){
				//put a worker on a core being different with main core
				lcore_id = rte_get_next_lcore( lcore_id, true, true );

				worker_context_t *smp = worker_alloc_init( context->config->stack_type );
				//general part
				smp->lcore_id      = lcore_id;
				smp->index         = worker_id;
				//keep a reference to its root
				smp->probe_context = context;
				//for DPDK
				smp->dpdk = mmt_alloc( sizeof( struct dpdk_worker_context_struct ));
				sem_init( &smp->dpdk->semaphore, 0, 0 );
				smp->dpdk->ring = p[reader_index].worker_rings[worker_index];


				context->smp[ worker_id ] = smp;
				worker_id++;
			}
		}
	}


	//start Workers
	for( worker_index=0; worker_index<total_nb_workers; worker_index++ ){
		ret = rte_eal_remote_launch( _worker_thread,
				context->smp[worker_index],
				context->smp[worker_index]->lcore_id );

		if( ret != 0 )
			rte_exit_failure("Cannot start worker %d.", worker_index);
	}


	//start readers
	for( port_index=0; port_index<nb_ports; port_index++ ){
		for( reader_index=0; reader_index<NB_READERS_PER_PORT; reader_index++ ){
			//ensure that reader and distributor run on 2 different lcores
			lcore_id = rte_get_next_lcore( lcore_id, true, true );

			struct reader_param *p = &reader_context[port_index][reader_index];

			sem_init( &p->semaphore, 0, 0 );
			p->pkts_dropped = rte_zmalloc( "pkt dropped by each worker",
					sizeof( uint64_t ) * p->nb_workers, RTE_CACHE_LINE_SIZE  );

			ret = rte_eal_remote_launch( _reader_thread, p, lcore_id );

			if( ret != 0 )
				rte_exit_failure("Cannot start reader %d of port %d.", reader_index, port_index);
		}
	}

	//do statistics
	struct timeval now;
	gettimeofday(& now, NULL);

	uint32_t next_stat_moment = now.tv_sec + context->config->stat_period;
	//periodically do a statistic of received/dropped packets
	while( ! context->is_exiting ){

		gettimeofday(& now, NULL);

		if( now.tv_sec < next_stat_moment  ){
			sleep( 1 );
			continue;
		}

		next_stat_moment += context->config->stat_period;

		//init stat numbers
		uint64_t packets_received = 0;
		uint64_t bytes_received   = 0;
		uint64_t packets_dropped  = 0;
		uint64_t bytes_dropped    = 0;
		struct rte_eth_stats stat;

		for( port_index=0; port_index<nb_ports; port_index++ ){
			uint8_t input_port = input_ports[ port_index ];

			if( rte_eth_stats_get( input_port, &stat ) )
				log_write( LOG_WARNING, "Cannot get statistic of port %d", input_port );
			else{
				context->traffic_stat.nic.drop    = stat.imissed  + stat.ierrors;
				context->traffic_stat.nic.receive = stat.ipackets + stat.imissed + stat.ierrors;
			}

			//for each reader
			for( reader_index=0; reader_index<NB_READERS_PER_PORT; reader_index++ ){
				struct reader_param *p = & reader_context[port_index][reader_index];

				packets_received += rte_atomic64_read( & p->stat_received.packets );
				bytes_received   += rte_atomic64_read( & p->stat_received.bytes );
				packets_dropped  += rte_atomic64_read( & p->stat_dropped.packets );
				bytes_dropped    += rte_atomic64_read( & p->stat_dropped.bytes );


//				snprintf( name, sizeof( name), "pool_%d_%d", input_port, reader_index);
//				struct rte_mempool *mempool = rte_mempool_lookup( name );
//				printf("\nmempool_%d_%d: use %8u, avail: %8u\n",
//						input_port,
//						reader_index,
//						rte_mempool_in_use_count( mempool ),
//						rte_mempool_avail_count( mempool ) );
			}

		}
		//update global statistic
		context->traffic_stat.mmt.packets.receive = packets_received;
		context->traffic_stat.mmt.packets.drop    = packets_dropped;
		context->traffic_stat.mmt.bytes.receive   = bytes_received;
		context->traffic_stat.mmt.bytes.drop      = bytes_dropped;

		context_print_traffic_stat( context, &now );
	}


//	printf("\n");
	//tell readers to exit
	is_continuous = false;
	// Waiting for all readers finish their jobs
	for( port_index=0; port_index<nb_ports; port_index++ )
		for( reader_index=0; reader_index < NB_READERS_PER_PORT; reader_index++ )
			sem_wait( & reader_context[port_index][reader_index].semaphore );

	//====> all readers finish



	// Waiting for all workers finish their jobs
	for( worker_index=0; worker_index < total_nb_workers; worker_index++ )
		sem_wait( & context->smp[worker_index]->dpdk->semaphore );

	//====> all readers and workers have been stopped <====//

	//update number of packets being dropped by Readers when its cannot be inserted into worker's rings
	// as the rings are full
	for( port_index=0; port_index<nb_ports; port_index++ )
		for( reader_index=0; reader_index < NB_READERS_PER_PORT; reader_index++ ){
			struct reader_param *p =  & reader_context[port_index][reader_index];

			//find worker by its ring address
			for( i=0; i<p->nb_workers; i++ )
				for( worker_index=0; worker_index<total_nb_workers; worker_index ++ ){
					if( context->smp[worker_index]->dpdk->ring == p->worker_rings[i] ){
						context->smp[worker_index]->stat.pkt_dropped = p->pkts_dropped[i];
						break;             //exit for worker_index
					}
				}
		}


	//statistic of each worker
	worker_print_common_statistics( context );


	_dpdk_capture_release( context );
	fflush( stdout );

	//close ports
	for( i=0; i<nb_ports; i++ ){
		_print_dpdk_stats( input_ports[i] );
		rte_eth_dev_stop(  input_ports[i] );
		rte_eth_dev_close( input_ports[i] );
	}
}
