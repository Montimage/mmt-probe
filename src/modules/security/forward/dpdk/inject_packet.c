/*
 * inject_packet.c
 *
 *  Created on: May 7, 2021
 *      Author: nhnghia
 *
 * This file implements the packet injection using DPDK
 */


#include <rte_common.h>
#include <rte_log.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_errno.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ether.h>
#include <rte_ip.h>

#include "../inject_packet.h"

struct inject_packet_context_struct{
	uint8_t  port_id;  //The port identifier of the Ethernet device
	struct rte_mempool *memory_pool;

	//we are in the general case: when we want to send x duplicates of a packet at the same time
	size_t pkt_dup_times; //number of duplicates to be sent
	struct rte_mbuf **mbuf_arr; //array of pointers to contain the duplicates' pointers
};

#define FATAL_ERROR(fmt, args...)                 \
	do{                                           \
		log_write( LOG_ERR, fmt, ##args );        \
		rte_exit(EXIT_FAILURE, fmt "\n", ##args); \
	}while(0)

/* Constants of the system */
#define MEMPOOL_NAME "mmt_5greplay_mempool"  // Name of the mem_pool
#define MEMPOOL_ELEM_SZ  2048                // Power of two greater than 1500
#define MEMPOOL_CACHE_SZ  512                // Max is 512
#define TX_QUEUE_SZ      4096                //
#define MAX_PKT_BURST      64

/* Struct for devices configuration for const defines see rte_ethdev.h */
static const struct rte_eth_conf port_conf = {
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	}
};

/* Struct for configuring each tx queue. These are default values */
static struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = 36,  /* Ring prefetch threshold */
		.hthresh = 0,   /* Ring host threshold */
		.wthresh = 0,   /* Ring writeback threshold */
	},
	.tx_free_thresh = 32
};


/**
 * Init each port with the configuration contained in the structs.
 * Every interface has nb_sys_cores queues
 */
static void init_port(int port_id) {

	int ret;
	if (!rte_eth_dev_is_valid_port(port_id))
		FATAL_ERROR( "Invalid port %d", port_id );

	if ( port_id >= rte_eth_dev_count_avail() )
			FATAL_ERROR("Cannot find port %d. There are only %d/%d available ports\n",
					port_id, rte_eth_dev_count_avail(), rte_eth_dev_count_total() );
	/* Configure device with '0' rx queues and 1 tx queue */
	ret = rte_eth_dev_configure(port_id, 0, 1, &port_conf);
	if (ret < 0)
		FATAL_ERROR("Error configuring the port %d", port_id);

	//free buffer after sending all duplicated packets
	//if( tx_conf.tx_free_thresh < pkt_dup_times )
	//	tx_conf.tx_free_thresh = pkt_dup_times;

	// Configure tx queue of current device on current NUMA socket.
	ret = rte_eth_tx_queue_setup(port_id, 0, TX_QUEUE_SZ, rte_socket_id(), &tx_conf);
	if (ret < 0)
		FATAL_ERROR(
				"Error configuring transmitting queue. Errno: %d (%d bad arg, %d no mem)",
				-ret, EINVAL, ENOMEM);

	// Start device
	ret = rte_eth_dev_start(port_id);
	if (ret < 0)
		FATAL_ERROR("Cannot start port\n");

	// this is needed only when receiving packets (not for sending packets)
	// Enable promiscuous mode for an Ethernet device
	//rte_eth_promiscuous_enable(port_id);
}


/**
 * This is called only one at the beginning to allocate a context
 * @param config
 * @return
 */
inject_packet_context_t* inject_packet_alloc( const probe_conf_t *probe_config ){
	const forward_packet_conf_t *conf = probe_config->forward_packet;
	inject_packet_context_t *context;

	int port_id = atoi( conf->output_nic ); //port number
	init_port( port_id );

	context = rte_malloc( NULL, (sizeof( struct inject_packet_context_struct ) ), RTE_CACHE_LINE_SIZE );;
	context->port_id = port_id;
	context->pkt_dup_times = conf->nb_copies;
	context->mbuf_arr = rte_malloc( NULL, (sizeof( struct rte_mbuf * ) * MAX_PKT_BURST ), RTE_CACHE_LINE_SIZE );;

	unsigned int nb_mbufs = RTE_MAX( MAX_PKT_BURST * ( MEMPOOL_CACHE_SZ + RTE_MBUF_DEFAULT_BUF_SIZE),
			8192U );
	// Create a mempool with per-core cache,
	// initializing every element for be used as mbuf, and allocating on the current NUMA node
	context->memory_pool = rte_pktmbuf_pool_create(MEMPOOL_NAME,
			nb_mbufs,
			MEMPOOL_CACHE_SZ,
			0,
			RTE_MBUF_DEFAULT_BUF_SIZE,
			rte_socket_id());

	if (context->memory_pool == NULL)
		FATAL_ERROR("Cannot create %s. Errno: %d (%s)", MEMPOOL_NAME, rte_errno, rte_strerror( rte_errno) );

	return context;
}


/**
 * This is call only one at the end to release the context
 * @param context
 */
void inject_packet_release( inject_packet_context_t *context ){
	if( !context )
		return;
	rte_free( context->mbuf_arr );
	rte_mempool_free( context->memory_pool );
	rte_free( context );
}


/**
 * Send a packet to the output NIC
 * @param context
 * @param packet_data
 * @param packet_size
 * @return number of packets being successfully injected to the output NIC
 */
int inject_packet_send_packet( inject_packet_context_t *context, const uint8_t *packet_data, uint16_t packet_size ){
	int i, max_burst;
	struct rte_mbuf *mbuf;
	int nb_total_sent = 0;

	rte_prefetch0( packet_data );
	int nb_pkt_to_send = context->pkt_dup_times;

	while( nb_pkt_to_send > 0) {

		max_burst = ( nb_pkt_to_send > MAX_PKT_BURST ? MAX_PKT_BURST :  nb_pkt_to_send);

		//allocate memory from memory_pool to contain packets and its duplicates to be sent
		//the allocated memory will be free by rte_eth_tx_burst
		if( unlikely( rte_pktmbuf_alloc_bulk( context->memory_pool, context->mbuf_arr, max_burst ) != 0 )){
			FATAL_ERROR("Not enough memory %d", max_burst );
			return false;
		}

		/* Copy the packet from the original one when sending on multiple */
		for( i=0; i<max_burst; i++){
			mbuf = context->mbuf_arr[i];
			if( unlikely( mbuf == NULL )){
				FATAL_ERROR("Not enough memory");
				return false;
			}

			mbuf->pkt_len = mbuf->data_len = packet_size;
			rte_memcpy((char*) mbuf->buf_addr + mbuf->data_off, packet_data, packet_size);
		}

		//try to send all packets in mbuf_arr
		i = 0;
		do{
			i += rte_eth_tx_burst( context->port_id, 0, context->mbuf_arr + i , max_burst - i);
		}while( i <  max_burst );

		nb_total_sent  += i;
		nb_pkt_to_send -= i;

	}

	return nb_total_sent;
}
