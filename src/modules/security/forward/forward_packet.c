/*
 * forward_packet.c
 *
 *  Created on: Jan 7, 2021
 *      Author: nhnghia
 */
#include <pcap/pcap.h>
#include "forward_packet.h"
#include "../../dpi/dpi_tool.h"
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
	uint64_t nb_dropped_packets;
	int raw_socket;
	uint8_t *packet_data; //a copy of a packet
	uint16_t packet_size;
	bool has_a_satisfied_rule; //whether there exists a rule that satisfied
	const ipacket_t *ipacket;
};

//TODO: need to be fixed in multi-threading
static forward_packet_context_t *cache = NULL;
static forward_packet_context_t * _get_current_context(){
	//TODO: need to be fixed in multi-threading
	MUST_NOT_OCCUR( cache == NULL );
	return cache;
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

static inline bool _send_packet_to_nic( forward_packet_context_t *context ){

	//returns the number of bytes written on success and -1 on failure.
	int ret = pcap_inject(context->pcap_handler, context->packet_data, context->packet_size );

	/*
	ret = sendto( context->raw_socket, buffer, pkt_size, 0,
		(struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
	*/
	return (ret > 0);
}

/**
 * Called only once to initial variables
 * @param config
 * @param dpi_handler
 * @return
 */
forward_packet_context_t* forward_packet_alloc( const probe_conf_t *config, mmt_handler_t *dpi_handler ){
	const forward_packet_conf_t *conf = config->forward_packet;
	if( ! conf->is_enable )
		return NULL;
	//TODO: limit only main thread (no multi-thread) for now
	ASSERT( config->thread->thread_count == 0, "5Greplay support using only main thread. Set thread-nb=0 in the .conf file." );
	ASSERT( config->reports.security->threads_size == 0, "5Greplay does not support multi-threading for now. Set security.thread-nb=0");
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

	context->packet_data = mmt_alloc( 0xFFFF ); //max size of a IP packet
	context->packet_size = 0;
	context->has_a_satisfied_rule = false;

//	context->raw_socket = sockfd;

	//TODO: not work in multi-threading
	cache = context;

	return context;
}

/**
 * Called only once to free variables
 * @param context
 */
void forward_packet_release( forward_packet_context_t *context ){
	if( !context )
		return;
	log_write_dual(LOG_INFO, "Number of packets being successfully forwarded: %"PRIu64", dropped: %"PRIu64,
			context->nb_forwarded_packets, context->nb_dropped_packets );
	if( context->pcap_handler ){
		pcap_close(context->pcap_handler);
		context->pcap_handler = NULL;
	}

	mmt_probe_free( context->packet_data );
	//if( context->raw_socket )
	//	close( context->raw_socket );

	mmt_probe_free( context );
}

void forward_packet_mark_being_satisfied( forward_packet_context_t *context ){
	context->has_a_satisfied_rule = true;
}


/**
 * This function must be called on each coming packet
 *   but before any rule being processed on the the current packet
 */
void forward_packet_on_receiving_packet_before_rule_processing(const ipacket_t * ipacket, forward_packet_context_t *context){
	context->ipacket = ipacket;
	context->packet_size = ipacket->p_hdr->caplen;
	context->has_a_satisfied_rule = false;
	//copy packet data, then modify packet's content
	memcpy(context->packet_data, ipacket->data, context->packet_size );
}

/**
 *  This function must be called on each coming packet
 *   but after all rules being processed on the current packet
 */
void forward_packet_on_receiving_packet_after_rule_processing( const ipacket_t * ipacket, forward_packet_context_t *context ){
	if( context->has_a_satisfied_rule == false )
		return;
	if( context->config->default_action  == ACTION_DROP ){
		context->nb_dropped_packets ++;
	} else {
		if( _send_packet_to_nic(context) )
			context->nb_forwarded_packets ++;
		else
			context->nb_dropped_packets ++;
	}

}


/**
 * This function is called by mmt-security when a FORWARD rule is satisfied
 *   and its if_satisfied="#drop"
 */
void mmt_probe_do_not_forward_packet(){
	//do nothing
	forward_packet_context_t *context = _get_current_context();
	context->nb_dropped_packets ++;
}

/**
 * This function is called by mmt-security when a FORWARD rule is satisfied
 *   and its if_satisfied="#update"
 *   or explicitly call forward_packet() in an embedded function
 */
void mmt_probe_forward_packet(){
	forward_packet_context_t *context = _get_current_context();
	if( _send_packet_to_nic(context) )
		context->nb_forwarded_packets ++;
}


//this function is implemented inside mmt-dpi to update NGAP protocol
extern uint32_t update_ngap_data( u_char *data, uint32_t data_size, const ipacket_t *ipacket, uint32_t proto_id, uint32_t att_id, uint64_t new_val );

/**
 * This function is called by mmt-security when a FORWARD rule is satisfied
 *   and its if_satisfied="#update( xx.yy, ..)"
 *   or explicitly call set_numeric_value in an embedded function
 */
void mmt_probe_set_attribute_number_value(uint32_t proto_id, uint32_t att_id, uint64_t new_val){
	forward_packet_context_t *context = _get_current_context();
	int ret = 0;
	ret = update_ngap_data(context->packet_data, context->packet_size, context->ipacket, proto_id, att_id, new_val );
	if( ! ret )
		DEBUG("Cannot update packet data for packet id%"PRIu64, context->ipacket->packet_id);
}
