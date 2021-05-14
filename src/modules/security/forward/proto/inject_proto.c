/*
 * inject_proto.c
 *
 *  Created on: May 14, 2021
 *      Author: nhnghia
 */


#include "../../../dpi/dpi_tool.h"
#include "../../../../lib/malloc.h"
#include "../../../../lib/memory.h"

#include "inject_proto.h"
#include "inject_sctp.h"

struct inject_proto_context_struct {
	inject_sctp_context_t *sctp;
};



inject_proto_context_t* inject_proto_alloc( const probe_conf_t *config ){
	inject_proto_context_t *context = mmt_alloc_and_init_zero( sizeof( inject_proto_context_t ));
	const forward_packet_conf_t *conf = config->forward_packet;
	int i;
	const forward_packet_target_conf_t *target;

	for( i=0; i<conf->target_size; i++ ){
		target = & conf->targets[i];
		switch( target->protocol ){
		case FORWARD_PACKET_PROTO_SCTP:
			context->sctp = inject_sctp_alloc(target, conf->nb_copies );
			break;
		default:
			ABORT("Does not support forwarding using a protocol to %s:%d", target->host, target->port );
		}
	}

	return context;
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
static inline int _get_sctp_data_offset( const ipacket_t *ipacket ){
	int sctp_index = get_protocol_index_by_id( ipacket, PROTO_SCTP_DATA );
	//not found SCTP
	if( sctp_index == -1 )
		return 0;
	//offset of sctp in packet
	return get_packet_offset_at_index(ipacket, sctp_index) + sizeof( struct sctp_datahdr );
}

int inject_proto_send_packet( inject_proto_context_t *context, const ipacket_t *ipacket, const uint8_t *packet_data, uint16_t packet_size ){
	int offset;
	offset = _get_sctp_data_offset( ipacket );
	if( offset >= 0 ){
		DEBUG("%"PRIu64" SCTP_DATA offset: %d", ipacket->packet_id, offset );
		inject_sctp_send_packet(context->sctp, packet_data + offset, packet_size - offset);
	}
	return INJECT_PROTO_NO_AVAIL;
}
void inject_proto_release( inject_proto_context_t *context ){
	if( context == NULL )
		return;
	inject_sctp_release(context->sctp);
	mmt_probe_free( context );
}
