/*
 * inject_packet.c
 *
 *  Created on: May 7, 2021
 *      Author: nhnghia
 *
 * This file implements the packet injection using libpcap
 */

#include <pcap/pcap.h>

#include "../inject_packet.h"

struct inject_packet_context_struct{
	pcap_t *pcap_handler;
};

/**
 * This is called only one at the beginning to allocate a context
 * @param config
 * @return
 */
inject_packet_context_t* inject_packet_alloc( const probe_conf_t *probe_config ){
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_errbuf[0] = '\0';

	const forward_packet_conf_t *conf = probe_config->forward_packet;

	pcap_t* pcap = pcap_open_live( conf->output_nic, conf->snap_len,
			conf->promisc, //promisc mode
			0, //timeout
			pcap_errbuf );

	//having error?
	if (pcap_errbuf[0]!='\0')
		ABORT("Cannot open NIC %s to forward packets: %s", conf->output_nic, pcap_errbuf);

	inject_packet_context_t *context = mmt_alloc_and_init_zero( sizeof( struct inject_packet_context_struct ));
	context->pcap_handler = pcap;
	return context;
}

/**
 * Send a packet to the output NIC
 * @param context
 * @param packet_data
 * @param packet_size
 * @return number of packets being successfully injected to the output NIC
 */
bool inject_packet_send_packet( inject_packet_context_t *context, const uint8_t *packet_data, uint16_t packet_size ){
	//returns the number of bytes written on success and -1 on failure.
	int ret = pcap_inject(context->pcap_handler, packet_data, packet_size );
	return (ret > 0);
}

/**
 * This is call only one at the end to release the context
 * @param context
 */
void inject_packet_release( inject_packet_context_t *context ){
	if( !context )
		return;
	if( context->pcap_handler ){
		pcap_close(context->pcap_handler);
		context->pcap_handler = NULL;
	}

	mmt_probe_free( context );
}
