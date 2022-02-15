/*
 * topology_report.c
 *
 *  Created on: Dec 13, 2018
 *          by: Huu-Nghia
 */

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <mobile/mmt_mobile.h>

#include<pthread.h>
#include <stdint.h>
#include "topology_report.h"


#include "../dpi.h"
#include "../dpi_tool.h"
#include "../../../lib/string_builder.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

enum{
	TOPO_ADD_ELEMENT = 1 , //element will be present into the topo but no link with other
	TOPO_ADD_LINK        , //add a link between two elements
	TOPO_REMOVE_LINK     , //rm  a link between two elements
	TOPO_REMOVE_ELEMENT    //rm an element and its links from the topo
};

struct lte_topo_report_struct{
	output_t *output;
	output_channel_conf_t output_channels;
	mmt_handler_t *dpi_handler;
};


static inline bool _build_msg_to_add_new_entity( char *message, const s1ap_entity_t *entity){
	int valid = 0;
	char message_tmp[ MAX_LENGTH_REPORT_MESSAGE ];
	char ip_str[INET_ADDRSTRLEN];

	//empty ip
	if( entity->ipv4 == 0 ){
		ip_str[0] = '\0';
	}else if( ! inet_ntop4( entity->ipv4, ip_str ) )
		return false;

	valid = 0;
	//depending on kind of entity, different information will be added
	switch( entity->type ){
	case S1AP_ENTITY_TYPE_UE:
		STRING_BUILDER_WITH_SEPARATOR( valid, message_tmp, MAX_LENGTH_REPORT_MESSAGE-valid, ",",
				__STR( entity->data.ue.imsi ),
				__INT( entity->data.ue.m_tmsi  ),
				__INT( entity->data.ue.gtp_teid )
		);
		break;
	case S1AP_ENTITY_TYPE_ENODEB:
		STRING_BUILDER_WITH_SEPARATOR( valid, message_tmp, MAX_LENGTH_REPORT_MESSAGE-valid, ",",
				__STR( entity->data.enb.name  )
		);
		break;
	case S1AP_ENTITY_TYPE_MME:
		STRING_BUILDER_WITH_SEPARATOR( valid, message_tmp, MAX_LENGTH_REPORT_MESSAGE-valid, ",",
				__STR( entity->data.mme.name  )
		);
		break;
	default:
		message_tmp[0] = '\0';
		break;
	}


	valid = 0;
	//common part of report
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( entity->id ),
			__INT( TOPO_ADD_ELEMENT ),
			__STR( ip_str  ),
			__INT( entity->type ),
			__ARR( message_tmp )
	);
	return true;
}


static inline bool _build_msg_to_add_new_link( char *message, const s1ap_entity_t *entity){
	if( entity->parent == 0 )
		return false;

	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( entity->id ),
			__INT( TOPO_ADD_LINK ),
			__INT( entity->parent )
	);
	return true;
}

static inline void _build_msg_to_rm_entity( char *message, const s1ap_entity_t *entity){
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( entity->id ),
			__INT( TOPO_REMOVE_ELEMENT )
	);
}

static inline void _build_msg_to_rm_link( char *message, const s1ap_entity_t *entity){
	int valid = 0;
	STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE, ",",
			__INT( entity->id ),
			__INT( TOPO_REMOVE_LINK )
	);
}

static void _got_s1ap_packet(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if( attribute->data == NULL || attribute->data_len < 2 )
		return;
	lte_topo_report_t *context = (lte_topo_report_t*)user_args;

	if( attribute->data == NULL )
		return;

	char message[ MAX_LENGTH_REPORT_MESSAGE ];


	const mmt_binary_var_data_t *binary_data = (mmt_binary_var_data_t *)attribute->data;
	const s1ap_entity_t *entity  = (s1ap_entity_t *) binary_data->data;


	//Depending on different status, we create different reports
	switch( entity->status ){

	//add new entity
	case S1AP_ENTITY_STATUS_ATTACHING:
		if( ! _build_msg_to_add_new_entity( message, entity ))
			return;
		break;

	//When an entity has been attached, we need to add a link between it and its parent
	case S1AP_ENTITY_STATUS_ATTACHED:
		if( !_build_msg_to_add_new_link( message, entity ) )
			return;
		break;


	case S1AP_ENTITY_STATUS_DETACHING:
		//special status for UEs
	case S1AP_ENTITY_STATUS_LOST_SIGNAL:
		_build_msg_to_rm_link( message, entity );
		break;

	//remove entity
	case S1AP_ENTITY_STATUS_DETACHED:
		_build_msg_to_rm_entity( message, entity );
		break;


	default:
		return;
	}

	DEBUG("%lu: %s", ipacket->packet_id, message );

	output_write_report( context->output, context->output_channels,
			LTE_TOPOLOGY_REPORT_TYPE,
			& ipacket->p_hdr->ts,
			message );
}

//This function is called by session_report.session_report_register to register HTTP extractions
static inline size_t _get_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t _handlers[] = {
		{.proto_id = PROTO_S1AP,          .att_id = S1AP_ATT_ENTITY_UE,      .handler = _got_s1ap_packet },
		{.proto_id = PROTO_S1AP,          .att_id = S1AP_ATT_ENTITY_ENODEB,  .handler = _got_s1ap_packet },
		{.proto_id = PROTO_S1AP,          .att_id = S1AP_ATT_ENTITY_MME,     .handler = _got_s1ap_packet },
	};

	*ret = _handlers;
	return (sizeof _handlers / sizeof( conditional_handler_t ));
}

lte_topo_report_t *lte_topo_report_register( mmt_handler_t *dpi_handler, bool is_enable, output_channel_conf_t channel, output_t *output){
	if( ! is_enable )
		return NULL;

	lte_topo_report_t *context = mmt_alloc_and_init_zero( sizeof( lte_topo_report_t ) );
	context->dpi_handler     = dpi_handler;
	context->output          = output;
	context->output_channels = channel;

	const conditional_handler_t* handlers = NULL;

	//register necessary attributes
	size_t size = _get_handlers_to_register( &handlers );
	dpi_register_conditional_handler( dpi_handler, size, handlers, context );

	return context;
}

void lte_topo_report_unregister( lte_topo_report_t *context){
	if( context == NULL )
		return;

	const conditional_handler_t* handlers = NULL;

	//unregister necessary attributes
	size_t size = _get_handlers_to_register( &handlers );
	dpi_unregister_conditional_handler( context->dpi_handler, size, handlers );


	mmt_probe_free(context);
}
