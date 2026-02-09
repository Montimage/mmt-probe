/*
 * lte_qos_report.c
 *
 *  Created on: Jun 25, 2019
 *          by: Huu-Nghia
 */



#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <mobile/mmt_mobile.h>

#include<pthread.h>
#include <stdint.h>
#include "lte_qos_report.h"


#include "../dpi.h"
#include "../dpi_tool.h"
#include "../../../lib/string_builder.h"
#include "../../../lib/log.h"
#include "../../../lib/malloc_ext.h"

struct lte_qos_report_struct{
	output_t *output;
	output_channel_conf_t output_channels;
	mmt_handler_t *dpi_handler;
	uint32_t ue_id;
	uint8_t qci;
	uint32_t teid;
};

static void _got_data(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
	if( attribute->data == NULL )
		return;

	lte_qos_report_t *context = (lte_qos_report_t*)user_args;
	switch( attribute->field_id ){
	case S1AP_ATT_UE_ID:
		context->ue_id = *(uint32_t *) attribute->data;
		break;
	case S1AP_ATT_TEID:
		context->teid = *(uint32_t *) attribute->data;
		break;
	case S1AP_ATT_QCI:
		context->qci = *(uint8_t *) attribute->data;
		break;
	default:
		break;
	}

	//report if all elements have been fulfilled
	if( context->qci != 0 && context->teid != 0 && context->ue_id != 0 ){
		int valid = 0;
		char message[ MAX_LENGTH_REPORT_MESSAGE ];
		STRING_BUILDER_WITH_SEPARATOR( valid, message, MAX_LENGTH_REPORT_MESSAGE-valid, ",",
				__INT( context->ue_id ),
				__INT( context->teid  ),
				__INT( context->qci )
		);

		DEBUG("%lu: %s", ipacket->packet_id, message );

		output_write_report( context->output, context->output_channels,
				LTE_QOS_REPORT_TYPE,
				& ipacket->p_hdr->ts,
				message );
		//reset data after reporting to avoid redundancy
		context->qci = 0;
	}
}

//This function is called by session_report.session_report_register to register HTTP extractions
static inline size_t _get_handlers_to_register( const conditional_handler_t **ret ){
	static const conditional_handler_t _handlers[] = {
		{.proto_id = PROTO_S1AP, .att_id = S1AP_ATT_UE_ID, .handler = _got_data },
		{.proto_id = PROTO_S1AP, .att_id = S1AP_ATT_TEID,  .handler = _got_data },
		{.proto_id = PROTO_S1AP, .att_id = S1AP_ATT_QCI,   .handler = _got_data },
	};

	*ret = _handlers;
	return (sizeof _handlers / sizeof( conditional_handler_t ));
}

lte_qos_report_t *lte_qos_report_register( mmt_handler_t *dpi_handler, bool is_enable, output_channel_conf_t channel, output_t *output){
	if( ! is_enable )
		return NULL;

	lte_qos_report_t *context = mmt_alloc_and_init_zero( sizeof( lte_qos_report_t ) );
	context->dpi_handler     = dpi_handler;
	context->output          = output;
	context->output_channels = channel;

	const conditional_handler_t* handlers = NULL;

	//register necessary attributes
	size_t size = _get_handlers_to_register( &handlers );
	dpi_register_conditional_handler( dpi_handler, size, handlers, context );

	return context;
}

void lte_qos_report_unregister( lte_qos_report_t *context){
	if( context == NULL )
		return;

	const conditional_handler_t* handlers = NULL;

	//unregister necessary attributes
	size_t size = _get_handlers_to_register( &handlers );
	dpi_unregister_conditional_handler( context->dpi_handler, size, handlers );


	mmt_probe_free(context);
}
