/*
 * dpdk_capture.c
 *
 *  Created on: Dec 20, 2016
 *      Author: montimage
 */
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#include "processing.h"

#ifdef DPDK
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


#define RX_RING_SIZE    4096
#define NUM_MBUFS       196609
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE      128

static uint8_t hash_key[40] = {
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A,
		0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A
};

static const struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
				.pthresh = 8,   /* Ring prefetch threshold */
				.hthresh = 8,   /* Ring host threshold */
				.wthresh = 0    /* Ring writeback threshold */
		},
		// .rx_free_thresh = 32,    /* Immediately free RX descriptors */
		.rx_drop_en     = 0
};

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
						.rss_key_len = 40,
						.rss_hf      = ETH_RSS_PROTO_MASK
				},
		},
		// .txmode = {
		// 		.mq_mode = ETH_MQ_TX_NONE,
		// },
};

void print_stats (void * args){
	struct rte_eth_stats stat;
	int i;
	static uint64_t good_pkt = 0, miss_pkt = 0, err_pkt = 0;
	struct mmt_probe_struct * probe = (struct mmt_probe_struct *) args;
	/* Print per port stats */
	//for (i = 1; i < 2; i++){
	i = atoi (probe->mmt_conf->input_source);
	rte_eth_stats_get(i, &stat);
	good_pkt += stat.ipackets;
	miss_pkt += stat.imissed;
	err_pkt  += stat.ierrors;

	//reset counters of stat to zero
	//		rte_eth_stats_reset( i );
	//}

        //probe->mmt_conf->report_length += snprintf(&probe->mmt_conf->report_msg[probe->mmt_conf->report_length],1024 - probe->mmt_conf->report_length,"%u,%"PRIu64",%"PRIu64",%f,%"PRIu64",%"PRIu64"",probe->mmt_conf->probe_id_number,good_pkt, miss_pkt,(float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt );

       printf ("[mmt-probe-0]{%u,%"PRIu64",%"PRIu64",%f,%"PRIu64",%"PRIu64"}\n",probe->mmt_conf->probe_id_number,good_pkt, miss_pkt,(float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt);
        printf("\nTOT:  %'9ld (recv), %'9ld (dr %3.2f%%), %'7ld (err) %'9ld (tot)\n\n",
			good_pkt, miss_pkt, (float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt );

}

static int
worker_thread(void *args_ptr){
	const uint8_t nb_ports = 1;
	uint8_t port;
	uint16_t i, ret = 0;
	uint16_t nb_rx;
	struct pkthdr header;
	struct timeval  time_now;
//	struct timespec time_now;
	struct rte_mbuf *bufs[BURST_SIZE];

	void  * data;

	header.user_args = NULL;

	struct smp_thread *th = (struct smp_thread *) args_ptr;
	mmt_probe_context_t * probe_context = get_probe_context_config();

//	printf("new handler: %p\n", th->mmt_handler );

	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		reset_microflows_stats(&th->iprobe.mf_stats[i]);
		th->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
		th->iprobe.mf_stats[i].application_id = i;
	}
	th->iprobe.instance_id = th->thread_number;
	// customized packet and session handling functions are then registered

	if(probe_context->enable_session_report == 1) {
		register_session_timer_handler(th->mmt_handler, print_ip_session_report, th);
		register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
		flowstruct_init(th); // initialize our event handler
		if (probe_context->condition_based_reporting_enable == 1)conditional_reports_init(th);// initialize our condition reports
		if (probe_context->radius_enable == 1)radius_ext_init(th); // initialize radius extraction and attribute event handler
	}
	set_default_session_timed_out(th->mmt_handler, probe_context->default_session_timeout);
	set_long_session_timed_out(th->mmt_handler, probe_context->long_session_timeout);
	set_short_session_timed_out(th->mmt_handler, probe_context->short_session_timeout);
	set_live_session_timed_out(th->mmt_handler, probe_context->live_session_timeout);

	if (probe_context->event_based_reporting_enable == 1)
		event_reports_init(th); // initialize our event reports
	if (probe_context->enable_security_report == 0 && probe_context->enable_security_report_multisession == 0)
		proto_stats_init( th );//initialise this before security_reports_init
	if (probe_context->enable_security_report == 1)
		security_reports_init(th);
	if (probe_context->enable_security_report_multisession == 1)
		security_reports_multisession_init(th);// should be defined before proto_stats_init


	/* Check that the port is on the same NUMA node as the polling thread
	 * for best performance.*/
//	for (port = 0; port < nb_ports; port++)
//		if (rte_eth_dev_socket_id( port ) > 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id())
//			printf("WARNING, port %u is on remote NUMA node to "
//					"polling thread.\n\tPerformance will "
//					"not be optimal. core_id = %u \n", port, rte_lcore_id());

//	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
//			rte_lcore_id());

	port = atoi (probe_context->input_source);
	/* Run until the application is quit or killed. */
	while ( likely( !do_abort )) {

		//printf ("do_abort = %u\n",do_abort);
		gettimeofday(&time_now, NULL); //TODO: change time add to nanosec
//		clock_gettime( CLOCK_REALTIME_COARSE, &time_now );

		//only happen periodically, e.g., each 5 seconds
		if( unlikely( time_now.tv_sec >= th->last_stat_report_time  ||
				th->pcap_current_packet_time >= th->pcap_last_stat_report_time )){
			th->report_counter++;
			th->last_stat_report_time      = time_now.tv_sec              + probe_context->stats_reporting_period;
			th->pcap_last_stat_report_time = th->pcap_current_packet_time + probe_context->stats_reporting_period;

			if (probe_context->enable_session_report == 1)
				process_session_timer_handler( th->mmt_handler );

			if (probe_context->enable_proto_without_session_stats == 1)
				iterate_through_protocols(protocols_stats_iterator, th);
		}

		//gettimeofday(&time_now, NULL); //TODO: change time add to nanosec
		/*Get burst of RX packets, from first port.*/
		nb_rx = rte_eth_rx_burst(port, th->thread_number, bufs, BURST_SIZE);

//		if( unlikely( nb_rx == 0 ))
//			nanosleep( (const struct timespec[]){{0, 50000L}}, NULL );

		header.ts = time_now;
//		header.ts.tv_usec = time_now.tv_nsec;

		for (i = 0; likely(i < nb_rx); i++){
			header.len         = (unsigned int) bufs[i]->pkt_len;
			header.caplen      = (unsigned int) bufs[i]->data_len;
			header.ts.tv_usec += 1;

			data = (bufs[i]->buf_addr + bufs[i]->data_off);

			packet_process( th->mmt_handler, &header, (u_char *) data );

			rte_pktmbuf_free( bufs[i] );
		}

		th->nb_packets += nb_rx;
	}

	//printf("thread %2d, nb_packets = %'9"PRIu64" \n", th->thread_number, th->nb_packets );
        printf ("[mmt-probe-1]{%u,%"PRIu64"}\n",th->thread_number, th->nb_packets);
        //pthread_spin_lock(&spin_lock);
        //probe_context->report_length += snprintf(probe_context->report_msg + probe_context->report_length - 2,1024 - probe_context->report_length,",%d,%"PRIu64"}",th->thread_number, th->nb_packets);
        //printf ("length = %u, msg = %s\n",probe_context->report_length,probe_context->report_msg);
        //pthread_spin_unlock(&spin_lock);
	if(th->mmt_handler != NULL){
		radius_ext_cleanup(th->mmt_handler); // cleanup our event handler for RADIUS initializations
		flowstruct_cleanup(th->mmt_handler); // cleanup our event handler
		th->report_counter++;
		if (probe_context->enable_proto_without_session_stats == 1)
			iterate_through_protocols( protocols_stats_iterator, th );
		if (cleanup_registered_handlers (th) == 0){
			fprintf(stderr, "Error while unregistering attribute  handlers thread_nb = %u !\n",th->thread_number);
		}
                pthread_spin_lock(&spin_lock);
		mmt_close_handler(th->mmt_handler);
		th->mmt_handler = NULL;
		pthread_spin_unlock(&spin_lock);
	}

	return 0;
}

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool, struct mmt_probe_struct * mmt_probe)
{
	int retval;
	uint16_t q;
	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, mmt_probe->mmt_conf->thread_nb, 0 , &port_conf_default);
	if (retval != 0){
		rte_exit(EXIT_FAILURE, "Cannot configure port %d (%s)\n", port, rte_strerror(retval) );
		return retval;
	}

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < mmt_probe->mmt_conf->thread_nb; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
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


/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
		lcore_main()
{
	for (;;) {
		sleep( 1 );
	}
}
int dpdk_capture (int argc, char **argv, struct mmt_probe_struct * mmt_probe){
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;
	int num_of_cores = 0;
	unsigned total_of_cores = rte_lcore_count();
	unsigned int lcore_id, last_lcore_id, master_lcore_id;
	char mmt_errbuf[1024];

	setlocale(LC_NUMERIC, "en_US.UTF-8");

	num_of_cores = mmt_probe->mmt_conf->thread_nb + 1;

	/* Check if we have enought cores */
	if ( total_of_cores < num_of_cores)
		rte_exit(EXIT_FAILURE, "This application does not have "
				"enough cores to run this application, check threads assigned \n");

	/* Number of network interfaces to be used  */
	nb_ports = 1;

	// nb_ports = rte_eth_dev_count();
	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	//	for (portid = 1; portid < 2; portid++)
	portid = atoi(mmt_probe->mmt_conf->input_source);
	if (port_init(portid, mbuf_pool, mmt_probe) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
				portid);


	mmt_probe->smp_threads = (struct smp_thread *) calloc(mmt_probe->mmt_conf->thread_nb,sizeof (struct smp_thread));
	if (mmt_probe->smp_threads == NULL){
		printf("ERROR: mmt_probe.smp_threads memory allocation \n");
	}

	int thread_nb   = 0;
	lcore_id        = 0;
	master_lcore_id = rte_get_master_lcore();

	/* Start worker_thread() on all the available slave cores but the last 1 */
	while ( thread_nb < mmt_probe->mmt_conf->thread_nb ){
		if ( rte_lcore_is_enabled( lcore_id ) && lcore_id != master_lcore_id){

			pthread_spin_init( &mmt_probe->smp_threads[thread_nb].lock, 0);
			mmt_probe->smp_threads[thread_nb].last_stat_report_time      = time(0);
			mmt_probe->smp_threads[thread_nb].pcap_last_stat_report_time = 0;
			mmt_probe->smp_threads[thread_nb].pcap_current_packet_time   = 0;
			//mmt_probe->smp_threads[thread_nb].nb_dropped_packets = 0;
			mmt_probe->smp_threads[thread_nb].nb_packets    = 0;
			mmt_probe->smp_threads[thread_nb].workers       = (worker_args_t *) calloc(1,sizeof (worker_args_t));
			mmt_probe->smp_threads[thread_nb].thread_number = thread_nb;
			mmt_probe->smp_threads[thread_nb].mmt_handler   = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
			if (! mmt_probe->smp_threads[thread_nb].mmt_handler ) { /* pcap error ?*/
				fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
				return EXIT_FAILURE;
			}
			mmt_probe->smp_threads[thread_nb].workers->lcore_id = lcore_id;


			rte_eal_remote_launch(worker_thread, (void *)&mmt_probe->smp_threads[thread_nb], lcore_id);
			//	printf("thread_id = %u, core_id = %u, last_lcore_id =%u \n",thread_nb,lcore_id,last_lcore_id);

			thread_nb ++;
		}
		lcore_id ++ ;
	}

	printf("[info] %d threads have been started!\n", thread_nb);

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;

}
#endif
