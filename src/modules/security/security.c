/*
 * security.c
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "security.h"
//dpi_message_set_data function to set data to message_t
#include <dpi_message_t.h>

#include <stdio.h>
#include <stdlib.h>

#include "../../lib/memory.h"
#include "../../lib/string_builder.h"

#define SECURITY_DPI_PACKET_HANDLER_ID 10

static inline bool _extract_data_for_specific_attribute( const ipacket_t *pkt, int dpi_data_type, message_t *msg, uint32_t proto_id, uint32_t att_id ){
	uint32_t *data_len = NULL;
	switch( proto_id ){
	case PROTO_TCP:
		switch( att_id ){
		case TCP_SESSION_PAYLOAD_UP:
			data_len = get_attribute_extracted_data( pkt, PROTO_TCP, TCP_SESSION_PAYLOAD_UP_LEN );
			goto __got_data_len;
		case TCP_SESSION_PAYLOAD_DOWN:
			data_len = get_attribute_extracted_data( pkt, PROTO_TCP, TCP_SESSION_PAYLOAD_DOWN_LEN );
			goto __got_data_len;
		}
		return false;
	default:
		return false;
	}

	//when we go to here, it means that proto_id == PROTO_TCP
	//and, att_id == TCP_SESSION_PAYLOAD_UP or TCP_SESSION_PAYLOAD_DOWN

	__got_data_len:
	if( data_len == NULL )
		return true;

	void *data = get_attribute_extracted_data( pkt, proto_id, att_id );
	if( data == NULL )
		return true;

	set_element_data_message_t( msg, proto_id, att_id, data, MMT_SEC_MSG_DATA_TYPE_BINARY, *data_len );
	return true;
}

/**
 * Convert a pcap packet to a message being understandable by mmt-security.
 * The function returns NULL if the packet contains no interested information.
 * Otherwise it creates a new memory segment to store the result message. One need
 * to use #free_message_t to free the message.
 */
static inline message_t* _get_packet_info( const ipacket_t *pkt, const proto_attribute_t **proto_atts, size_t proto_atts_count ){
	int i;
	void *data;
	int type;
	bool ret;
	message_t *msg = create_message_t( proto_atts_count );
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;

	//get a list of proto/attributes being used by mmt-security
	for( i=0; i<proto_atts_count; i++ ){
		ret = _extract_data_for_specific_attribute( pkt, proto_atts[i]->dpi_type, msg, proto_atts[i]->proto_id, proto_atts[i]->att_id );

		//if this proto/att has been processed, we donot need to call dpi_message_set_data
		if( ret )
			continue;
		dpi_message_set_data( pkt, proto_atts[i]->dpi_type, msg, proto_atts[i]->proto_id, proto_atts[i]->att_id );
	}

	return msg;
}

/**
 * This function is called by mmt-dpi for each incoming packet containing registered proto/att.
 * It gets interested information from the #ipkacet to a message then sends the
 * message to mmt-security.
 */
static int _security_packet_handler( const ipacket_t *ipacket, void *args ) {
	security_context_t *wrapper = (security_context_t *)args;
	if (wrapper == NULL) return 0;
	message_t *msg = _get_packet_info( ipacket, wrapper->proto_atts, wrapper->proto_atts_count );

	//if there is no interested information
	//TODO: to check if we still need to send timestamp/counter to mmt-sec?
	if( unlikely( msg->elements_count == 0 )){
		free_message_t( msg );
		return 0;
	}

	mmt_sec_process( wrapper->sec_handler, msg );

	return 0;
}

/**
 * This function inits security rules
 * @return
 */
int security_open( const char *excluded_rules ){
	log_write( LOG_INFO, "Start MMT-Security %s", mmt_sec_get_version_info() );
	//exclude rules in rules_mask
	return mmt_sec_init( excluded_rules );
}


void security_close(){
	mmt_sec_close();
}


/**
 * A function to be called when a rule is validated
 * Note: this function can be called from one or many different threads,
 *       ==> be carefully when using static or shared variables inside it
 */
static void _print_security_verdict(
		const rule_info_t *rule,		//rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,			    //moment (by order of packet) the rule is validated
		const mmt_array_t * trace,//historic messages that validates the rule
		void *user_data					//#user-data being given in register_security
){
	security_context_t *security_context = (security_context_t *) user_data;

	//depending on the configuration of security.report-rule-description,
	// we include the description of the rule or not
	const char *description = security_context->config->is_report_rule_description? rule->description : "";
	const char *exec_trace  = mmt_convert_execution_trace_to_json_string( trace, rule );


	struct timeval ts;
	mmt_sec_decode_timeval(timestamp, &ts );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;
	STRING_BUILDER_WITH_SEPARATOR( offset, message, sizeof( message ), ",",
			__INT( rule->id ),
			__STR( verdict_type_string[verdict] ),
			__STR( rule->type_string ),
			__STR( description ),
			__ARR( exec_trace ) //string without quotes
	);

	output_write_report( security_context->output,
				security_context->config->output_channels,
				SECURITY_REPORT_TYPE,
				&ts,
				message);
}

static inline bool _register_additional_attributes_if_need( mmt_handler_t *dpi_handler, uint32_t proto_id, uint32_t att_id, uint32_t *add_att_id ){
	//we need IP_HEADER_LEN to calculate length of IP_OPTS
	if( proto_id == PROTO_IP && att_id == IP_OPTS ){
		if (!register_extraction_attribute( dpi_handler, PROTO_IP, IP_HEADER_LEN)){
			log_write( LOG_WARNING, "Cannot register protocol/attribute ip.header_len");
			return false;
		}
		*add_att_id = IP_HEADER_LEN;
		return true;
	}

	if( proto_id == PROTO_TCP && att_id == TCP_SESSION_PAYLOAD_UP ){
		if (!register_extraction_attribute( dpi_handler, PROTO_IP, TCP_SESSION_PAYLOAD_UP_LEN)){
			log_write( LOG_WARNING, "Cannot register protocol/attribute tcp.tcp_session_payload_up_len");
			return false;
		}
		*add_att_id =  TCP_SESSION_PAYLOAD_UP_LEN;
		return true;
	}
	if( proto_id == PROTO_TCP && att_id == TCP_SESSION_PAYLOAD_DOWN ){
		if (!register_extraction_attribute( dpi_handler, PROTO_IP, TCP_SESSION_PAYLOAD_DOWN_LEN)){
			log_write( LOG_WARNING, "Cannot register protocol/attribute tcp.tcp_session_payload_down_len");
			return false;
		}
		*add_att_id =  TCP_SESSION_PAYLOAD_DOWN_LEN;
		return true;
	}

	return false;
}

/**
 *
 * @param dpi_handler
 * @param threads_count: if 0, security will use the lcore of caller
 * @param cores_id
 * @param rules_mask
 * @param verbose
 * @param callback
 * @param user_data
 * @return
 */
security_context_t* security_worker_alloc_init( const security_conf_t *config,
		mmt_handler_t *dpi_handler, const uint32_t *cores_id,
		bool verbose, output_t *output, bool is_enable_tcp_reassembly ){
	size_t threads_count = config->threads_size;
	int i;

	int att_registed_offset = 0;
	const int att_registed_length = 10000;
	char att_registed[10000];
	uint32_t add_att_id;
	if( ! config->is_enable )
		return NULL;

	//init
	security_context_t *ret = mmt_alloc_and_init_zero(sizeof( security_context_t ));
	ret->dpi_handler = dpi_handler;
	ret->config      = config;
	ret->output      = output;
	pthread_mutex_init( &ret->mutex, NULL);
	//init mmt-sec to verify the rules
	ret->sec_handler = mmt_sec_register( threads_count, cores_id, config->rules_mask, verbose, _print_security_verdict, ret );

	//register protocols and their attributes using by mmt-sec
	ret->proto_atts_count =  mmt_sec_get_unique_protocol_attributes((void*) &ret->proto_atts );

	bool is_need_tcp_reassembly = false;

	for( i=0; i<ret->proto_atts_count; i++ ){
		//mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		if( register_extraction_attribute( dpi_handler, ret->proto_atts[i]->proto_id, ret->proto_atts[i]->att_id ) == 0){
			log_write( LOG_WARNING, "Cannot register protocol/attribute %s.%s", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );
		}
		else if( verbose )
			att_registed_offset += snprintf( att_registed + att_registed_offset, MAX( att_registed_length - att_registed_offset, 0),
					"%s.%s,", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );

		//for some attribute, we need to register another attribute
		// example, we need `tcp_session_payload_up_len` when one wants to access `tcp_session_payload_up`
		 if( _register_additional_attributes_if_need( dpi_handler, ret->proto_atts[i]->proto_id, ret->proto_atts[i]->att_id, &add_att_id ) ){
			 if( verbose )
				 att_registed_offset += snprintf( att_registed + att_registed_offset, MAX( att_registed_length - att_registed_offset, 0),
			 					"%s.%s,", ret->proto_atts[i]->proto,
								get_attribute_name_by_protocol_and_attribute_ids(ret->proto_atts[i]->proto_id, add_att_id ));
		 }

		 if( !is_need_tcp_reassembly
				 && ret->proto_atts[i]->proto_id == PROTO_TCP
				 && (ret->proto_atts[i]->att_id == TCP_SESSION_PAYLOAD_UP || ret->proto_atts[i]->att_id == TCP_SESSION_PAYLOAD_DOWN ))
			 	 is_need_tcp_reassembly = true;
	}

	if( is_need_tcp_reassembly ){
#ifdef TCP_REASSEMBLY_MODULE
		if( ! is_enable_tcp_reassembly )
		log_write( LOG_WARNING, "The rules used tcp.tcp_session_payload_up or tcp.tcp_session_payload_down will not work as 'enable-tcp-reassembly = false'" );
#else
		log_write( LOG_WARNING, "The rules used tcp.tcp_session_payload_up or tcp.tcp_session_payload_down will not work as TCP_REASSEMBLY_MODULE is not enable" );
#endif
	}

	if( verbose ){
		rule_info_t const* const* rules_array = NULL;
		//remove the last comma
		att_registed[ strlen( att_registed ) - 1 ] = '\0';
		log_write( LOG_INFO,"Registered %u proto.atts to process %zu rules: %s",
				ret->proto_atts_count,
				mmt_sec_get_rules_info( &rules_array ),
				att_registed );
	}

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler( dpi_handler, SECURITY_DPI_PACKET_HANDLER_ID, _security_packet_handler, ret );

	return ret;
}


/**
 * Stop and free mmt_security
 * @param wrapper
 * @return
 */
size_t security_worker_release( security_context_t* ret ){
	size_t alerts_count = 0;

	if( unlikely( ret == NULL || ret->sec_handler == NULL ) )
		return 0;

	alerts_count = mmt_sec_unregister( ret->sec_handler );

	ret->sec_handler = NULL;

	unregister_packet_handler (ret->dpi_handler, SECURITY_DPI_PACKET_HANDLER_ID );
	mmt_probe_free( ret );

	return alerts_count;
}
