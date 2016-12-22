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
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#include "processing.h"

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 64

#define NUM_MBUFS 524287
#define MBUF_CACHE_SIZE 512
#define BURST_SIZE 4096

#define RX_RINGS_COUNT 1
static uint64_t total_pkt [20];
mmt_handler_t *mmt_handler;

//static uint64_t total_pkt2 = 0;
//static uint64_t total_pkt3 = 0;
//static uint64_t total_pkt4 = 0;
/*typedef struct pkthdr {
	struct timeval ts;   *< time stamp that indicates the packet arrival time
	unsigned int caplen; *< length of portion of the packet that is present
	unsigned int len;    *< length of the packet (off wire)
	unsigned int original_caplen; *< Original capture len of the packet when it was captured by interface - not count with reassembly data
	unsigned int original_len; *< Original capture len of the packet when it was captured by interface - not count with reassembly data
	void * user_args;    *< Pointer to a user defined argument. Can be NULL, it will not be used by the library.
} pkthdr_t;

struct packet_element {
	struct pkthdr header;
	u_char *data;
};*/
const uint16_t tx_rings = 4; /* Struct for configuring each rx queue. These are default values */
const uint16_t rx_rings = 4;
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

	printf("\ntotal1: %lu \n",total_pkt[0]);
	printf("\ntotal2: %lu \n",total_pkt[1]);
	printf("\ntotal3: %lu \n",total_pkt[2]);
	printf("\ntotal4: %lu \n",total_pkt[3]);

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

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint8_t port, struct rte_mempool *mbuf_pool)
{


	int retval;
	uint16_t q;

	//      if (port >= rte_eth_dev_count())
	//              return -1;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf_default);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, RX_RING_SIZE,
				rte_eth_dev_socket_id(port), &rx_conf, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, TX_RING_SIZE,
				rte_eth_dev_socket_id(port), NULL);
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

int get_packet(uint8_t port, int q, struct rte_mbuf **bufs){
	uint16_t nb_rx;
	int i=0;
	//struct rte_mbuf *bufs[BURST_SIZE];
	struct pkthdr header;
	static struct packet_element *pkt;
	struct timeval time_now;
	struct timeval time_add;
	struct timeval time_new;

	gettimeofday(&time_now, NULL);
	void  * data;
	time_add.tv_sec = 0;
	time_add.tv_usec = 0;

	nb_rx = rte_eth_rx_burst(port, q, bufs, BURST_SIZE);
	//printf ("queue = %u , nb_rx1 = %u \n", q, nb_rx1);
	if (unlikely(nb_rx == 0)){
		//nanosleep( (const struct timespec[]){{0, 10L}}, NULL );
		return 1;
	}
	total_pkt[q] += nb_rx;

	//free all packets received
	for( i=0; likely( i < nb_rx ); i++ ){
		time_add.tv_usec += 1;
		header.len    = (unsigned int)bufs[i]->pkt_len;
		header.caplen = (unsigned int) bufs[i]->data_len;
		timeradd(&time_now, &time_add, &time_new);
		header.ts     = time_new;
		header.user_args = NULL;
		data = (bufs[i]->buf_addr + bufs[i]->data_off);
		packet_process( mmt_handler, &header, (u_char *)data );
		rte_pktmbuf_free( bufs[i] );
	}
	return 0;
}
/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
static __attribute__((noreturn)) void
		lcore_main(void)
{
	const uint8_t nb_ports = rte_eth_dev_count();
	uint8_t port;
	int q;
	struct rte_mbuf *bufs[BURST_SIZE];
	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
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
		/*
		 * Receive packets on a port
		 */
		for (port = 0; port < nb_ports; port++)
		{

			/* Get burst of RX packets, from first port of pair. */
			for( q = 0; q < rx_rings; q++ )
			{
				get_packet (port,q, bufs);


				/* Send burst of TX packets, to second port of pair. */
				//                      const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0,
				//                                      bufs, nb_rx);
				//
				//                      /* Free any unsent packets. */
				//                      if (unlikely(nb_tx < nb_rx)) {
				//                              uint16_t buf;
				//                              for (buf = nb_tx; buf < nb_rx; buf++)
				//                                      rte_pktmbuf_free(bufs[buf]);
				//                      }

			}

		}

	}
}



int dpdk_capture (int argc, char **argv){
	struct rte_mempool *mbuf_pool;
	unsigned nb_ports;
	uint8_t portid;
	char mmt_errbuf[1024];
	mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	/* Initialize the Environment Abstraction Layer (EAL). */
	argv[1] = argv[argc - 2];
	argv[2] = argv[argc - 1];
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	setlocale(LC_NUMERIC, "en_US.UTF-8");

	/* Create handler for SIGINT for CTRL + C closing and SIGALRM to print stats*/
	signal(SIGINT, sig_handler);
	signal(SIGALRM, alarm_routine);

	alarm(1);

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = 1; // rte_eth_dev_count();

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
			MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	for (portid = 0; portid < nb_ports; portid++)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu8 "\n",
					portid);

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the master core only. */
	lcore_main();

	return 0;

}
