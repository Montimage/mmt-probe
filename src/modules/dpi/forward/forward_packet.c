/*
 * forward_packet.c
 *
 *  Created on: Jan 7, 2021
 *      Author: nhnghia
 */
#include <pcap/pcap.h>
#include "forward_packet.h"
#include "../dpi_tool.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"
#include "process_packet.h"

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

struct forward_packet_context_struct{
	pcap_t *pcap_handler;
	const forward_packet_conf_t *config;
	uint64_t nb_forwarded_packets;
	int raw_socket;
};

//TODO: need to be fixed in multi-threading
static struct packet_forward{
	//to update attribute's value
	uint32_t proto_id, att_id;
	uint64_t new_val;
	forward_action_t action;
	bool is_need_to_update_packet;
}cache;

static void _reset_cache(){
	//by default we forward packets and no need to modify them before forwarding
	cache.is_need_to_update_packet = false;
	cache.action = ACTION_FORWARD;
}

static pcap_t * _create_pcap_handler( const forward_packet_conf_t *conf ){
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';
	pcap_t* pcap = pcap_open_live( conf->output_nic, conf->snap_len,
			conf->promisc, //promisc mode
			0, //timeout
			pcap_errbuf );

	//having error?
	if (pcap_errbuf[0]!='\0')
		ABORT("Cannot open NIC %s to forward packets: %s", conf->output_nic, pcap_errbuf);

	return pcap;
}

/*
static int _create_raw_socket( const forward_packet_conf_t *conf ){
	int sockfd =-1;
	struct ifreq if_idx;
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if( sockfd == -1 )
		ABORT("Cannot create raw socket to send packets");

	// Get the index of the interface to send on
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, conf->output_nic, IFNAMSIZ-1);

	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
		perror("SIOCGIFINDEX");

	return sockfd;
}
*/

/**
 * Called only once to initial variables
 * @param worker_index
 * @param config
 * @param dpi_handler
 * @return
 */
forward_packet_context_t* forward_packet_start( uint16_t worker_index, const probe_conf_t *config, mmt_handler_t *dpi_handler ){
	const forward_packet_conf_t *conf = config->forward_packet;
	if( ! conf->is_enable )
		return NULL;

	//TODO: limit only main thread (no multi-thread) for now
	ASSERT( config->thread->thread_count == 0, "5Greplay support using only main thread. Set thread-nb=0 in the .conf file." );

	pcap_t *pcap = _create_pcap_handler( conf );
	if( !pcap )
		return NULL;
/*
	int sockfd = _create_raw_socket(conf);
	if( sockfd == -1)
		return NULL;
*/

	forward_packet_context_t *context = mmt_alloc_and_init_zero( sizeof( forward_packet_context_t ));
	context->config = conf;
	context->pcap_handler = pcap;

//	context->raw_socket = sockfd;

	_reset_cache();
	return context;
}

/**
 * Called only once to free variables
 * @param context
 */
void forward_packet_stop( forward_packet_context_t *context ){
	if( !context )
		return;
	log_write_dual(LOG_INFO, "Number of packets being forwarded successfully: %"PRIu64, context->nb_forwarded_packets );
	if( context->pcap_handler ){
		pcap_close(context->pcap_handler);
		context->pcap_handler = NULL;
	}

	//if( context->raw_socket )
	//	close( context->raw_socket );

	mmt_probe_free( context );
}

extern uint32_t update_ngap_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, uint64_t new_val );


/**
 * This function must be called on each coming packet
 */
int forward_packet_callback_on_receiving_packet(const ipacket_t * ipacket, forward_packet_context_t *context){
	if( unlikely(!context ))
		return 0;

	if( cache.action == ACTION_DROP ){
		DEBUG("Drop packet %"PRIu64, ipacket->packet_id );
		_reset_cache(); //reset to default action
		return 0;
	}

	pcap_t *pcap = context->pcap_handler;
	size_t pkt_len = ipacket->p_hdr->caplen;

	u_char buffer[0xFFFF]; //2bytes length of packet size
	int ret = 0;
	if( cache.is_need_to_update_packet ){
		//copy packet data, then modify packet's content
		memcpy(buffer, ipacket->data, pkt_len );
		if(!update_ngap_data(buffer, pkt_len, ipacket, cache.proto_id, cache.att_id, cache.new_val )){
			DEBUG("Cannot update packet data for packet id%"PRIu64, ipacket->packet_id);
		}
		ret = pcap_inject(pcap, buffer, pkt_len);
	}
	else
		ret = pcap_inject(pcap, ipacket->data, pkt_len);

	/*
	ret = sendto( context->raw_socket, buffer, pkt_size, 0,
			(struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
	*/
	if( ret ==  pkt_len)
		context->nb_forwarded_packets ++;
	//else
	//	printf("error writing\n");
	_reset_cache(); //reset to default action
	return ret;
}

void set_forward_action(forward_action_t act){
	//TODO need to be fixed in multithreading
	cache.action = act;
}
void set_attribute_number_value(uint32_t proto_id, uint32_t att_id, uint64_t new_val){
	//TODO need to be fixed in multithreading
	cache.proto_id = proto_id;
	cache.att_id   = att_id;
	cache.new_val  = new_val;
	cache.is_need_to_update_packet = true;
}
