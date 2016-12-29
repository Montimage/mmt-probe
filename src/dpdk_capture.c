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
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#include "processing.h"

#define RX_RING_SIZE 4096
#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 4096
#define MAX_PKTS_BURST 4096
#define RING_SIZE 16384

static uint64_t total_pkt [20];

const uint16_t tx_rings = 4; /* Struct for configuring each rx queue. These are default values */
//const uint16_t rx_rings = 4;
static uint8_t hash_key[40] = { 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, 0x6D, 0x5A, };
static const struct rte_eth_rxconf rx_conf = {
		.rx_thresh = {
				.pthresh = 0,   /* Ring prefetch threshold */
				.hthresh = 0,   /* Ring host threshold */
				.wthresh = 0,   /* Ring writeback threshold */
		},
		.rx_free_thresh = 0,    /* Immediately free RX descriptors */
		.rx_drop_en = 1
};

static const struct rte_eth_conf port_conf_default = {
		.rxmode = {
				//.max_rx_pkt_len = ETHER_MAX_LEN,
				.mq_mode        = ETH_MQ_RX_RSS,
				.max_rx_pkt_len = ETHER_MAX_LEN,
				.split_hdr_size = 0,
				.header_split = 0,   /**< Header Split disabled */
				.hw_ip_checksum = 0, /**< IP checksum offload disabled */
				.hw_vlan_filter = 0, /**< VLAN filtering disabled */
				.hw_strip_crc= 0
		},
		.rx_adv_conf = {
				.rss_conf = {
						.rss_key = hash_key,
						.rss_hf = ETH_RSS_PROTO_MASK,
				},
		},
		.txmode = {
				.mq_mode = ETH_MQ_TX_NONE,
		},
};

void print_stats (void){
	struct rte_eth_stats stat;
	int i;
	static uint64_t good_pkt = 0, miss_pkt = 0, err_pkt = 0;
	int thread_nb = 10;

	/* Print per port stats */
	for (i = 0; i < 1; i++){
		rte_eth_stats_get(i, &stat);
		good_pkt += stat.ipackets;
		miss_pkt += stat.imissed;
		err_pkt  += stat.ierrors;

		printf("\nP %2d %'9ld pps %'4.1f Mbps (received), %'7ld/pps (dropped %3.2f%%), %'9ld pps (total)",
				i, stat.ipackets,
				stat.ibytes * 8.0 /1000/1000,
				stat.imissed,
				(float)stat.imissed/(stat.ipackets+stat.imissed)*100,
				stat.ipackets+stat.imissed );

		//reset counters of stat to zero
		rte_eth_stats_reset( i );
	}
	printf("\n-------------------------------------------------");
	printf("\nTOT:  %'9ld (recv), %'9ld (dr %3.2f%%), %'7ld (err) %'9ld (tot)\n\n",
			good_pkt, miss_pkt, (float)miss_pkt/(good_pkt+miss_pkt+err_pkt)*100, err_pkt, good_pkt+miss_pkt+err_pkt );

	for (i = 0; i < thread_nb; i++)
		printf("\n Packet_processed total thread %u: %lu \n",i,total_pkt[i]);


}
/* Signal handling function */
static void sig_handler(int signo)
{
	/* Print the per port stats  */
	printf("\n\nQUITTING...\n");

	print_stats();

	exit(0);
}


void alarm_routine (__attribute__((unused)) int unused){

	/* Print per port stats */
	print_stats();

	/* Schedule an other print */
	//alarm(1);
	signal(SIGALRM, alarm_routine);
}

int packet_handler_dpdk(const ipacket_t * ipacket, void * args) {
	struct worker_args *args_ptr;

	args_ptr = (struct worker_args *) args;
	total_pkt[args_ptr->lcore_id] = ipacket->packet_id;
	return 0;
}

/**
 * Get the previous enabled lcore ID
 * @param id
 *  The current lcore ID
 * @return
 *   The previous enabled lcore ID or the current lcore
 *   ID if it is the first available core.
 */
static unsigned int
get_previous_lcore_id(unsigned int id)
{
	int i;

	for (i = id - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return id;
}

/**
 * Get the last enabled lcore ID
 *
 * @return
 *   The last enabled lcore ID.
 */
static unsigned int
get_last_lcore_id(void)
{
	int i;

	for (i = RTE_MAX_LCORE - 1; i >= 0; i--)
		if (rte_lcore_is_enabled(i))
			return i;
	return 0;
}

static int
worker_thread(void *args_ptr)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	uint16_t i, ret = 0;
	char mmt_errbuf[1024];
	uint16_t nb_rx;
	struct pkthdr header;
	struct timeval time_now;
	struct timeval time_add;
	struct timeval time_new;
	struct rte_mbuf *bufs[BURST_SIZE];
	void  * data;
	time_add.tv_sec = 0;
	time_add.tv_usec = 0;

	struct smp_thread *th = (struct smp_thread *) args_ptr;

	//struct worker_args * workers= (struct worker_args *) args_ptr;
	th->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	if (!th->mmt_handler) { /* pcap error ?*/
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
		return EXIT_FAILURE;
	}
	//Register a packet handler, it will be called for every processed packet
	register_packet_handler(th->mmt_handler, 10, packet_handler_dpdk, (void *)args_ptr);


	//th->iprobe.data_out = NULL;
	//th->iprobe.radius_out = NULL;
	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		reset_microflows_stats(&th->iprobe.mf_stats[i]);
		th->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
		th->iprobe.mf_stats[i].application_id = i;
	}
	th->iprobe.instance_id = th->thread_number;
	// customized packet and session handling functions are then registered

	if(mmt_probe.mmt_conf->enable_session_report == 1) {
		register_session_timer_handler(th->mmt_handler, print_ip_session_report, th);
		register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
		flowstruct_init(th); // initialize our event handler
		if (mmt_probe.mmt_conf->condition_based_reporting_enable == 1)conditional_reports_init(th);// initialize our condition reports
		if (mmt_probe.mmt_conf->radius_enable == 1)radius_ext_init(th); // initialize radius extraction and attribute event handler
		set_default_session_timed_out(th->mmt_handler, mmt_probe.mmt_conf->default_session_timeout);
		set_long_session_timed_out(th->mmt_handler, mmt_probe.mmt_conf->long_session_timeout);
		set_short_session_timed_out(th->mmt_handler, mmt_probe.mmt_conf->short_session_timeout);
		set_live_session_timed_out(th->mmt_handler, mmt_probe.mmt_conf->live_session_timeout);
	}
	if (mmt_probe.mmt_conf->event_based_reporting_enable == 1)event_reports_init(th); // initialize our event reports
	if (mmt_probe.mmt_conf->enable_security_report == 0)proto_stats_init(th);//initialise this before security_reports_init
	if (mmt_probe.mmt_conf->enable_security_report == 1)security_reports_init(th);

	/* Check that the port is on the same NUMA node as the polling thread
	 * for best performance.*/
	for (port = 0; port < nb_ports; port++)
		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\nCore %u receiving packets. [Ctrl+C to quit]\n",
			rte_lcore_id());


	/* Run until the application is quit or killed. */
	for (;;) {

		/* Receive packets on a port*/
		gettimeofday(&time_now, NULL);
	        port = 0;
			/*Get burst of RX packets, from first port of pair.*/
			//get_packet (port,workers->lcore_id,args_ptr);
			nb_rx = rte_eth_rx_burst(port, th->thread_number, bufs, BURST_SIZE);
			for (i = 0; i < nb_rx; i++){
				time_add.tv_usec += 1;
				header.len    = (unsigned int)bufs[i]->pkt_len;
				header.caplen = (unsigned int) bufs[i]->data_len;
				timeradd(&time_now, &time_add, &time_new);
				header.ts     = time_new;
				header.user_args = NULL;
				data = (bufs[i]->buf_addr + bufs[i]->data_off);
				packet_process( th->mmt_handler, &header, (u_char *)data );
				rte_pktmbuf_free( bufs[i] );
			}
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
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < mmt_probe->mmt_conf->thread_nb; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), &rx_conf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet port. */
	retval = rte_eth_dev_start(port);
	if (retval < 0)
		return retval;
	/* Display the port MAC address. */
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			" %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			(unsigned)port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

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

	}
}
int dpdk_capture (int argc, char **argv, struct mmt_probe_struct * mmt_probe){
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;
	int num_of_cores = 0;
	unsigned int lcore_id, last_lcore_id, master_lcore_id;

	argv[1] = argv[argc - 2];
	argv[2] = argv[argc - 1];
	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	setlocale(LC_NUMERIC, "en_US.UTF-8");

	/* Create handler for SIGINT for CTRL + C closing and SIGALRM to print stats*/
	//signal(SIGINT, sig_handler);
	signal(SIGALRM, alarm_routine);

	alarm(1);

	argc -= ret;
	argv += ret;
	num_of_cores = mmt_probe->mmt_conf->thread_nb +1;

	/* Check if we have enought cores */
	if (rte_lcore_count() < num_of_cores)
		rte_exit(EXIT_FAILURE, "Error, This application does not have "
				"enough cores to run this application, check threads assigned \n");


	/* Number of network interfaces to be used  */
	nb_ports = 1;


	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool, mmt_probe) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	last_lcore_id   = get_last_lcore_id();
	master_lcore_id = rte_get_master_lcore();



	mmt_probe->smp_threads = (struct smp_thread *) calloc(mmt_probe->mmt_conf->thread_nb,sizeof (struct smp_thread));
	if (mmt_probe->smp_threads == NULL){
		printf("ERROR: mmt_probe.smp_threads memory allocation \n");
	}

	int thread_nb = 0;
	lcore_id = 0;
	/* Start worker_thread() on all the available slave cores but the last 1 */
	while (thread_nb < mmt_probe->mmt_conf->thread_nb){
		if (lcore_id <= get_previous_lcore_id(last_lcore_id)){
			if (rte_lcore_is_enabled(lcore_id) && lcore_id != master_lcore_id){
				mmt_probe->smp_threads[thread_nb].last_stat_report_time = time(0);
				mmt_probe->smp_threads[thread_nb].pcap_last_stat_report_time = 0;
				mmt_probe->smp_threads[thread_nb].pcap_current_packet_time = 0;
				//workers[thread_nb].mmt_probe->smp_threads->null_pkt.pkt.data = NULL;
				mmt_probe->smp_threads[thread_nb].nb_dropped_packets = 0;
				mmt_probe->smp_threads[thread_nb].nb_packets         = 0;
				mmt_probe->smp_threads[thread_nb].workers = (worker_args_t *) calloc(1,sizeof (worker_args_t));
				//snprintf(mmt_probe->smp_threads[thread_nb].workers->rx_to_workers, MAX_MESS,"%u", lcore_id );
				//mmt_probe->smp_threads[thread_nb].workers->ring_in = rte_ring_create(mmt_probe->smp_threads[thread_nb].workers->rx_to_workers, RING_SIZE, rte_socket_id(),RING_F_SP_ENQ);
				mmt_probe->smp_threads[thread_nb].thread_number = thread_nb;
				rte_eal_remote_launch(worker_thread, (void *)&mmt_probe->smp_threads[thread_nb], lcore_id);
				printf("thread_id = %u, core_id = %u\n",thread_nb,lcore_id);
				thread_nb ++;
			}
			lcore_id++;
		}
	}

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;

}
