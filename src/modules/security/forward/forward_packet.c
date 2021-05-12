/*
 * forward_packet.c
 *
 *  Created on: Jan 7, 2021
 *      Author: nhnghia
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <time.h>

#include "forward_packet.h"
#include "../../dpi/dpi_tool.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"
#include "process_packet.h"
#include "inject_packet.h"



struct forward_packet_context_struct{
	const forward_packet_conf_t *config;
	uint64_t nb_forwarded_packets;
	uint64_t nb_dropped_packets;
	uint8_t *packet_data; //a copy of a packet
	uint16_t packet_size;
	bool has_a_satisfied_rule; //whether there exists a rule that satisfied
	const ipacket_t *ipacket;

	inject_packet_context_t *injector;

	struct{
		uint32_t nb_packets, nb_bytes;
		time_t last_time;
	}stat;
};

//TODO: need to be fixed in multi-threading
static forward_packet_context_t *cache = NULL;
static forward_packet_context_t * _get_current_context(){
	//TODO: need to be fixed in multi-threading
	MUST_NOT_OCCUR( cache == NULL );
	return cache;
}

struct sctp_datahdr {
        uint8_t type;
        uint8_t flags;
        uint16_t length;
        uint32_t tsn;
        uint16_t stream;
        uint16_t ssn;
        uint32_t ppid;
        //uint8_t payload[0];
    };

//keep only SCTP payload in context->packet_data
static inline int _get_sctp_data_offset( forward_packet_context_t *context ){
	const ipacket_t *ipacket = context->ipacket;
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	//not found SCTP
	if( sctp_index == -1 )
		return 0;
	//offset of sctp in packet
	return get_packet_offset_at_index(ipacket, sctp_index) + sizeof( struct sctp_datahdr );
}

static inline bool _send_packet_to_nic( forward_packet_context_t *context ){
	int offset = _get_sctp_data_offset( context );
	if( offset == 0 )
		return false;

	DEBUG("%"PRIu64" SCTP_DATA offset: %d", context->ipacket->packet_id, offset );
	int ret = inject_packet_send_packet(context->injector,  context->packet_data + offset, context->packet_size - offset);
	if( ret > 0 )
		context->nb_forwarded_packets += ret;

	context->stat.nb_packets += ret;
	context->stat.nb_bytes   += ( ret * context->packet_size );
	time_t now = time(NULL); //return number of second from 1970
	if( now != context->stat.last_time ){
		float interval = (now - context->stat.last_time);
		log_write_dual(LOG_INFO, "Statistics of forwarded packets %.2f pps, %.2f bps",
				context->stat.nb_packets   / interval,
				context->stat.nb_bytes * 8 / interval);
		//reset stat
		context->stat.last_time  = now;
		context->stat.nb_bytes   = 0;
		context->stat.nb_packets = 0;
	}
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

	forward_packet_context_t *context = mmt_alloc_and_init_zero( sizeof( forward_packet_context_t ));
	context->config = conf;
	//init packet injector that can be PCAP or DPDK (or other?)
	context->injector = inject_packet_alloc(config);

	context->packet_data = mmt_alloc( 0xFFFF ); //max size of a IP packet
	context->packet_size = 0;
	context->has_a_satisfied_rule = false;
	context->stat.last_time = time(NULL);

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
	if( context->injector ){
		inject_packet_release( context->injector );
		context->injector = NULL;
	}

	mmt_probe_free( context->packet_data );
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
	//whether the current packet is handled by a security rule ?
	// if yes, we do nothing
	if( context->has_a_satisfied_rule )
		return;
	if( context->config->default_action  == ACTION_DROP ){
		context->nb_dropped_packets ++;
	} else {
		if( ! _send_packet_to_nic(context) )
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
	_send_packet_to_nic(context);
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
