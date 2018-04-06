/*
 * dpdk_capture.c
 *
 *  Created on: Dec 20, 2016
 *      Author: montimage
 */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#include "processing.h"
#include "lib/security.h"

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_common.h>
#include <rte_errno.h>
#include <rte_malloc.h>
#include <rte_mempool.h>
#include <rte_ring.h>
#include <errno.h>


#define RX_RING_SIZE    4096 	/* Size for each RX ring*/
#define NUM_MBUFS       65535  /* Total size of MBUFS */
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE      128  	/* Burst size to receive packets from RX ring */

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
static const struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
				.pthresh = 8,   /* Ring prefetch threshold */
				.hthresh = 8,   /* Ring host threshold */
				.wthresh = 0    /* Ring writeback threshold */
		},
		// .rx_free_thresh = 32,    /* Immediately free RX descriptors */
		.rx_drop_en     = 0
};

/* eth port configuration struct */
static const struct rte_eth_conf port_conf_default = {
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
		// .txmode = {
		// 		.mq_mode = ETH_MQ_TX_NONE,
		// },
};

/**
 * Print statistic of captured packets given by DPDK
 * @param mmt_conf
 */
static inline void _print_dpdk_stats( const mmt_probe_context_t * mmt_conf ){
	struct rte_eth_stats stat;
	uint64_t good_pkt, miss_pkt, err_pkt;
	uint8_t input_port;

	input_port = atoi( mmt_conf->input_source );
	rte_eth_stats_get( input_port, &stat );

	good_pkt = stat.ipackets;
	miss_pkt = stat.imissed;
	err_pkt  = stat.ierrors;

	//probe->mmt_conf->report_length += snprintf(&probe->mmt_conf->report_msg[probe->mmt_conf->report_length],1024 - probe->mmt_conf->report_length,"%u,%"PRIu64",%"PRIu64",%f,%"PRIu64",%"PRIu64"",probe->mmt_conf->probe_id_number,good_pkt, miss_pkt,(float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt );

	printf ("[mmt-probe-0]{%u,%"PRIu64",%"PRIu64",%f,%"PRIu64",%"PRIu64"}\n",
			 mmt_conf->probe_id_number, good_pkt, miss_pkt, (float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt + miss_pkt + err_pkt );
	printf("\nTOT:  %'9ld (recv), %'9ld (dr %3.2f%%), %'7ld (err) %'9ld (tot)\n\n",
			good_pkt, miss_pkt, (float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt );
}


static int _worker_thread( void *args_ptr ){
	uint8_t input_port;
	uint16_t i, ret = 0;
	uint16_t nb_rx;
	struct pkthdr pkt_header;
	struct timeval  time_now;
	//	struct timespec time_now;
	struct rte_mbuf *bufs[BURST_SIZE];

	void  * pkt_data;

	struct smp_thread *th = (struct smp_thread *) args_ptr;
	const mmt_probe_context_t * mmt_conf = get_probe_context_config();

	sec_wrapper_t * security = NULL;

	//initialize parameters of this worker
	th->last_stat_report_time      = time(0);
	th->pcap_last_stat_report_time = 0;
	th->pcap_current_packet_time   = 0;
	//th->nb_dropped_packets = 0;
	th->nb_packets                 = 0;

	//	printf("new handler: %p\n", th->mmt_handler );

	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		reset_microflows_stats( &th->iprobe.mf_stats[i] );
		th->iprobe.mf_stats[i].application    = get_protocol_name_by_id(i);
		th->iprobe.mf_stats[i].application_id = i;
	}

	th->iprobe.instance_id = th->thread_index;
	// customized packet and session handling functions are then registered

	if(mmt_conf->enable_session_report == 1) {
		register_session_timer_handler(th->mmt_handler, print_ip_session_report, th);
		register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
		flowstruct_init(th); // initialize our event handler
		if (mmt_conf->condition_based_reporting_enable == 1)conditional_reports_init(th);// initialize our condition reports
		if (mmt_conf->radius_enable == 1)radius_ext_init(th); // initialize radius extraction and attribute event handler
	}

	//set timeouts
	set_default_session_timed_out( th->mmt_handler, mmt_conf->default_session_timeout);
	set_long_session_timed_out(    th->mmt_handler, mmt_conf->long_session_timeout);
	set_short_session_timed_out(   th->mmt_handler, mmt_conf->short_session_timeout);
	set_live_session_timed_out(    th->mmt_handler, mmt_conf->live_session_timeout);

	if (mmt_conf->event_based_reporting_enable == 1)
		event_reports_init(th); // initialize our event reports
	if (mmt_conf->enable_security_report == 0 && mmt_conf->enable_security_report_multisession == 0)
		proto_stats_init( th );
	if (mmt_conf->enable_security_report == 1)
		security_reports_init(th);
	if (mmt_conf->enable_security_report_multisession == 1)
		security_reports_multisession_init(th);


	/* Check that the port is on the same NUMA node as the polling thread
	 * for best performance.*/
	//	for (port = 0; port < nb_ports; port++)
	//		if (rte_eth_dev_socket_id( port ) > 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id())
	//			printf("WARNING, port %u is on remote NUMA node to "
	//					"polling thread.\n\tPerformance will "
	//					"not be optimal. core_id = %u \n", port, rte_lcore_id());

	//	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
	//			rte_lcore_id());

	//security2
	if( mmt_conf->security2_enable ){
		//lcore_id on which security2 will run
		uint32_t *sec_cores_mask = malloc( sizeof( uint32_t ) * mmt_conf->security2_threads_count );

		for( i=0; i < mmt_conf->security2_threads_count; i++ )
			sec_cores_mask[ i ] = th->security2_lcore_id + i;

		security = register_security( th->mmt_handler,
				mmt_conf->security2_threads_count,
				sec_cores_mask, mmt_conf->security2_rules_mask,
				th->thread_index == 0,//false, //true,
				//this callback will be called from one or many different threads (depending on #security2_threads_count)
				//print verdict only if output to file or redis is enable
				( mmt_conf->output_to_file_enable == 1 && mmt_conf->security2_output_channel[0] )
				|| ( mmt_conf->redis_enable == 1 &&  mmt_conf->security2_output_channel[1] )
				|| ( mmt_conf->kafka_enable == 1 &&  mmt_conf->security2_output_channel[2] ) ? security_print_verdict : NULL,
				th );

		free( sec_cores_mask );
	}
	//


	input_port = atoi( mmt_conf->input_source );
	pkt_header.user_args = NULL;

	/* Run until the application is quit or killed. */
	while ( likely( !do_abort )) {

		//printf ("do_abort = %u\n",do_abort);
		gettimeofday(&time_now, NULL); //TODO: change time add to nanosec
		//		clock_gettime( CLOCK_REALTIME_COARSE, &time_now );

		//only happen periodically, e.g., each 5 seconds
		if( unlikely( time_now.tv_sec >= th->last_stat_report_time  ||
				th->pcap_current_packet_time >= th->pcap_last_stat_report_time )){
			th->report_counter++;
			th->last_stat_report_time      = time_now.tv_sec              + mmt_conf->stats_reporting_period;
			th->pcap_last_stat_report_time = th->pcap_current_packet_time + mmt_conf->stats_reporting_period;

			if (mmt_conf->enable_session_report == 1)
				process_session_timer_handler( th->mmt_handler );

			if (mmt_conf->enable_proto_without_session_stats == 1 || mmt_conf->enable_IP_fragmentation_report == 1)
				iterate_through_protocols(protocols_stats_iterator, th);
		}

		// Get burst of RX packets, from first port
		nb_rx = rte_eth_rx_burst( input_port, th->thread_index, bufs, BURST_SIZE );

		if( nb_rx == 0 ){
//			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
		}else{
			pkt_header.ts = time_now;

			for (i = 0; likely(i < nb_rx); i++){
				pkt_header.len         = (unsigned int) bufs[i]->pkt_len;
				pkt_header.caplen      = (unsigned int) bufs[i]->data_len;
				pkt_header.ts.tv_usec += 1; //suppose that each packet comes after one micro-second

				pkt_data = (bufs[i]->buf_addr + bufs[i]->data_off);

				rte_prefetch2( pkt_data );
				packet_process( th->mmt_handler, &pkt_header, (u_char *) pkt_data );

				rte_pktmbuf_free( bufs[i] );
			}

			th->nb_packets += nb_rx;
		}
	}

	if( mmt_conf->security2_enable ){
		//get number of packets being processed by security
		uint64_t msg_count  = security->msg_count;
		//free security
		size_t alerts_count = unregister_security( security );

		printf ("[mmt-probe-1]{%3d,%9"PRIu64",%9"PRIu64",%7zu}\n",th->thread_index, th->nb_packets, msg_count, alerts_count );
	}else
		printf ("[mmt-probe-1]{%3d,%9"PRIu64"}\n",th->thread_index, th->nb_packets );

	radius_ext_cleanup( th->mmt_handler ); // cleanup our event handler for RADIUS initializations
	flowstruct_cleanup( th->mmt_handler ); // cleanup our event handler
	th->report_counter++;
	if ( mmt_conf->enable_proto_without_session_stats == 1 || mmt_conf->enable_IP_fragmentation_report == 1)
		iterate_through_protocols( protocols_stats_iterator, th );
	if ( cleanup_registered_handlers (th) == 0 )
		fprintf(stderr, "Error while unregistering attribute  handlers thread_nb = %u !\n",th->thread_index);

	//finish, wake up the main thread
	sem_post( &th->sem_wait );

	return 0;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int _port_init(uint8_t port, struct mmt_probe_struct * mmt_probe){
	struct rte_mempool *mbuf_pool;
	int retval;
	uint16_t q;
	char pool_name[100];


	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, mmt_probe->mmt_conf->thread_nb, 0 , &port_conf_default);
	if (retval != 0){
		rte_exit(EXIT_FAILURE, "Cannot configure port %d (%s)\n", port, rte_strerror(retval) );
		return retval;
	}

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < mmt_probe->mmt_conf->thread_nb; q++) {
		sprintf( pool_name, "pool_%d", q );

		// Creates a new mempool in memory to hold the mbufs.
		mbuf_pool = rte_pktmbuf_pool_create( pool_name, NUM_MBUFS,
					MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

		if (mbuf_pool == NULL)
			rte_exit(EXIT_FAILURE, "Cannot create mbuf_pool for queue %d of port %d\n", q, port );

		retval = rte_eth_rx_queue_setup( port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id( port ), &rx_conf, mbuf_pool);

		if (retval < 0){
			rte_exit(EXIT_FAILURE, "Cannot init queue %d of port %d (%s)\n", q, port, rte_strerror(retval) );
		}
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);

	if (retval < 0){
		rte_exit(EXIT_FAILURE, "Cannot start port %d\n", port );
		return retval;
	}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable( port );

	return 0;
}


int dpdk_capture (int argc, char **argv, struct mmt_probe_struct * mmt_probe){

	uint8_t input_port;
	const unsigned nb_ports        = 1,
	               total_of_cores  = rte_lcore_count(),
	               master_lcore_id = rte_get_master_lcore();

	unsigned lcore_id;
	char mmt_errbuf[1024];
	//configuration of one thread of probe
	struct smp_thread *th;
	//global configuration
	const mmt_probe_context_t *mmt_conf = mmt_probe->mmt_conf;
	int thread_index;

	setlocale( LC_NUMERIC, "en_US.UTF-8" );

	//we need at least one core for main thread and <n> cores for workers
	if ( total_of_cores < 1 + mmt_conf->thread_nb )
		rte_exit(EXIT_FAILURE, "This application does not have "
				"enough cores to run this application, check threads assigned \n");

	// Initialize input port
	input_port = atoi( mmt_conf->input_source );

	if ( _port_init(input_port, mmt_probe) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
				input_port);

	mmt_probe->smp_threads = (struct smp_thread *) calloc( mmt_conf->thread_nb, sizeof (struct smp_thread) );
	if (mmt_probe->smp_threads == NULL){
		printf("ERROR: mmt_probe.smp_threads memory allocation \n");
		exit( 1 );
	}

	lcore_id    = 0;
	thread_index = 0;

	/* Initialize the workers */
	while ( thread_index < mmt_conf->thread_nb ){
		//put a worker on a core being different with main core
		if ( rte_lcore_is_enabled( lcore_id ) && lcore_id != master_lcore_id){
			th = &mmt_probe->smp_threads[thread_index];

			pthread_spin_init( &th->lock, 0);
			th->thread_index = thread_index;
			th->lcore_id     = lcore_id;
			th->mmt_handler  = mmt_init_handler( DLT_EN10MB, 0, mmt_errbuf );
#ifdef HTTP_RECONSTRUCT_MODULE
			th->list_http_session_data = NULL;
#endif			
			if (! th->mmt_handler ) { /* pcap error ?*/
				fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
				return EXIT_FAILURE;
			}
			thread_index ++;
		}
		lcore_id ++ ;
	}

	lcore_id ++;

	//config security2
	if( mmt_conf->security2_enable ){
		//initialize security for each worker
		for( thread_index=0; thread_index< mmt_conf->thread_nb; thread_index++ ){
			th = &mmt_probe->smp_threads[thread_index];

			//lcore_id on that security threads will run
			th->security2_lcore_id = lcore_id + thread_index * mmt_conf->security2_threads_count;
		}
	}

	//start workers
	for( thread_index=0; thread_index< mmt_conf->thread_nb; thread_index++ ){
		th = &mmt_probe->smp_threads[thread_index];
		sem_init( &th->sem_wait, 0, 0 );
		rte_eal_remote_launch( _worker_thread, th, th->lcore_id );
	}

	printf( "INFO: %d threads have been started!\n", thread_index );

	// Waiting for all workers finish their jobs
	//rte_eal_mp_wait_lcore();
	for( thread_index=0; thread_index< mmt_conf->thread_nb; thread_index++ ){
		th = &mmt_probe->smp_threads[thread_index];
		sem_wait( &th->sem_wait );
	}

	//All workers finished their jobs

	//statistic of DPDK
	_print_dpdk_stats( mmt_conf );

	//close dpi handler
	for( thread_index=0; thread_index< mmt_conf->thread_nb; thread_index++ )
		mmt_close_handler( mmt_probe->smp_threads[thread_index].mmt_handler );
	
	//release security rules
	if( mmt_conf->security2_enable )
		close_security();
	
	return 0;

}
