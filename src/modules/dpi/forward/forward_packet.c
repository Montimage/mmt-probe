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

struct forward_packet_context_struct{
	pcap_t *pcap_handler;
	const forward_packet_conf_t *config;
	uint64_t nb_forwarded_packets;
};

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

	pcap_t *pcap = _create_pcap_handler( conf );
	if( !pcap )
		return NULL;

	forward_packet_context_t *context = mmt_alloc_and_init_zero( sizeof( forward_packet_context_t ));
	context->config = conf;
	context->pcap_handler = pcap;
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
	if( context->pcap_handler )
		pcap_close(context->pcap_handler);
	mmt_probe_free( context );
}

/**
 * This function must be called on each coming packet
 */
int forward_packet_callback_on_receiving_packet(const ipacket_t * ipacket, forward_packet_context_t *context){
	if( unlikely(!context ))
		return 0;

	pcap_t *pcap = context->pcap_handler;
	size_t pkt_size = ipacket->p_hdr->caplen;
	int ret = pcap_inject(pcap, ipacket->data, pkt_size);
	if( ret ==  pkt_size)
		context->nb_forwarded_packets ++;
	//else
	//	printf("error writing\n");
	return ret;
}

