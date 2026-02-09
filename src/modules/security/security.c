/*
 * security.c
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 *
 *  One MMT-Probe worker thread will create n security thread by calling security_worker_alloc_init.
 *  Number of security thread is designed by config->threads_size when passing to the function above.
 *
 *  +--------+        +-------------+
 *  | worker |======> | sec. thread |
 *  | thread |  ||    +-------------+
 *  +--------+  ||    +-------------+
 *               ====>| sec. thread |
 *              ||    +-------------+
 *              ||    +-------------+
 *               ====>| sec. thread |
 *                    +-------------+
 *
 * Each time a worker thread receives a packet, _security_packet_handler is called to parse the packet and
 *  then, encapsulates the extracted data from the packet to a security message.
 *  The message is then sent to a buffer of MMT-Security to be able to access by the sec. thread.
 *  The message will be freed by MMT-Security when it does not need the message any more.
 *
 * If a sec. thread detects an alert, it will call _print_security_verdict to print out the alert.
 *
 * Depending on the parameter ignore_remain_flow, the rest of a flow can be ignored if an alert was detected on that flow.
 * This will increase the verification performance.
 */


#include "security.h"
//dpi_message_set_data function to set data to message_t
#include <dpi_message_t.h>

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../lib/memory.h"
#include "../../lib/log.h"
#include "../../lib/string_builder.h"
#include "../../lib/malloc_ext.h"

#define SECURITY_DPI_PACKET_HANDLER_ID 10

#define IS_CFG_INOGRE( x ) (x->config->ignore_remain_flow )


/*
 * return available room inside a message
 */
static inline uint32_t _get_msg_room( const message_t * msg ){
	uint32_t used_room = msg->elements_count * SIZE_OF_MMT_MEMORY_T +  msg->_data_index + SIZE_OF_MMT_MEMORY_T;

	return ( msg->_data_length <= used_room )? 0 : (msg->_data_length - used_room);
}

/**
 * Get index of i-th proto_id in a protocol hierarchy
 * @return
 *   -1 if proto_id does not exist in the hierarchy
 *   number is index of proto_id in the hierarchy
 */
static inline int _find_proto_index( int proto_id, int encap_index, const proto_hierarchy_t *proto_hierarchy ){
	int proto_order = 0, last_i = -1, i;
   //no session => no IP
   if( proto_hierarchy == NULL )
      return last_i;

	for( i=0; i<proto_hierarchy->len; i++ )
		if( proto_hierarchy->proto_path[i] == proto_id ){
			proto_order ++;
			last_i = i;
			if( proto_order == encap_index )
				return i;
		}
	return last_i;
}

static inline bool _extract_data_for_specific_attribute(security_context_t *context, const ipacket_t *pkt, int dpi_data_type, message_t *msg, uint32_t proto_id, uint32_t att_id ){
	uint32_t *data_len = NULL;
	void *data = NULL;

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

	case PROTO_IP:
		if( context->config->ip_encapsulation_index == CONF_IP_ENCAPSULATION_INDEX_FIRST )
			return false;
		//find index
		int proto_index = _find_proto_index( PROTO_IP, context->config->ip_encapsulation_index, pkt->proto_hierarchy );
		//does not exist IP in this packet => do not need to go further
		if( proto_index == -1 )
			return true;
		data = get_attribute_extracted_data_at_index( pkt, proto_id, att_id, proto_index );
		if( data == NULL )
			return true;
		if( dpi_data_type == MMT_DATA_POINTER )
			dpi_message_set_void_data( pkt, data, msg, proto_id, att_id );
		else
			dpi_message_set_dpi_data( data, dpi_data_type, msg, proto_id, att_id );
		return true;
		break;
	default:
		return false;
	}

	//when we go to here, it means that proto_id == PROTO_TCP
	//and, att_id == TCP_SESSION_PAYLOAD_UP or TCP_SESSION_PAYLOAD_DOWN

	__got_data_len:
	if( data_len == NULL )
		return true;

	uint32_t room_size = _get_msg_room( msg );
	if(  *data_len  > room_size ){
		log_write( LOG_INFO, "Not enough room to contain %d bytes of %d.%d (avail. %d). Need to increase \"input.max_message_size\"",
				*data_len, proto_id, att_id, room_size );
		return true;
	}

	//get the whole data of a tcp flow
	// this may lead a problem of memory as a TCP flow may tranfer a huge data amount
	data = get_attribute_extracted_data( pkt, proto_id, att_id );
	if( data == NULL )
		return true;


	//append data to a security message that will be sent to MMT-Security
	set_element_data_message_t( msg, proto_id, att_id, data, MMT_SEC_MSG_DATA_TYPE_BINARY, *data_len );

	return true;
}

/**
 * This function is called by mmt-dpi for each incoming packet containing registered proto/att.
 * It gets interested information from the #ipkacet to a message then sends the
 * message to mmt-security.
 */
static int _security_packet_handler( const ipacket_t *ipacket, void *args ) {
	int i;
	bool ret;

	security_context_t *context = (security_context_t *)args;

	MUST_NOT_OCCUR( context == NULL, "args parameter must not be NULL"); //this must not happen

	uint64_t session_id = 0;

	//when parameter ignore_remain_flow is active
	if( IS_CFG_INOGRE( context )){
		session_id = get_session_id_from_packet( ipacket );
		//check if we can ignore this packet

		bool can_ignore =  mmt_sec_is_ignore_remain_flow( context->sec_handler, session_id );

		//the first part of the flow has been examined and we got at least one alert from that part
		// => we do not need to continue to examine the rest of the flow
		if( can_ignore ){
			return 0;
		}
	}

	/* We need to process this packet*/

	/* Convert a pcap packet to a message being understandable by mmt-security.
	 * The function returns NULL if the packet contains no interested information.
	 * Otherwise it creates a new memory segment to store the result message.
	 * One need to use #free_message_t to free the message.
	 */
	message_t *msg = create_message_t( context->proto_atts_count );

	//add other information to the message, such as, timestamp, packet_id, session_id
	msg->timestamp = mmt_sec_encode_timeval( &ipacket->p_hdr->ts );
	msg->counter   = ipacket->packet_id;

	//when parameter ignore_remain_flow is active,
	// we need to remember the session_id of the packet
	if( IS_CFG_INOGRE( context ))
		msg->flow_id = session_id;

	//get a list of proto/attributes being used by mmt-security
	for( i=0; i<context->proto_atts_count; i++ ){

		ret = _extract_data_for_specific_attribute( context, ipacket, context->proto_atts[i]->dpi_type, msg,
				context->proto_atts[i]->proto_id, context->proto_atts[i]->att_id );

		//if this proto/att has been processed, we do not need to call dpi_message_set_data
		if( ret )
			continue;

		dpi_message_set_data( ipacket, context->proto_atts[i]->dpi_type, msg,
				context->proto_atts[i]->proto_id, context->proto_atts[i]->att_id );
	}

	//if there is no interested information
	if( unlikely( msg->elements_count == 0 )){
		free_message_t( msg );
		return 0;
	}

	//give the message to MMT-Security
	mmt_sec_process( context->sec_handler, msg );

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

static inline const uint32_t _get_ip_src_from_trace(int event_id, const mmt_array_t *const trace) {
	const message_t *msg;
	const message_element_t *me;
	uint64_t value = 0;
	int j;
	if( event_id >= trace->elements_count )
		return 0;
	msg = trace->data[event_id];
	if( !msg )
		return 0;
	for (j = 0; j < msg->elements_count; j++) {
		me = &msg->elements[j];
		if (me && me->proto_id == PROTO_IP && me->att_id == IP_SRC)
			return *(uint32_t *) me->data;
	}
	return 0;
}

/**
 * A function to be called when a rule is validated
 * Note: this function can be called from one or many different threads,
 *       ==> be carefully when using static or shared variables inside it
 */
static void _print_security_verdict(
		const rule_info_t *rule,        //rule being validated
		enum verdict_type verdict,      //DETECTED, NOT_RESPECTED
		uint64_t timestamp,             //moment (by time) the rule is validated
		uint64_t counter,               //moment (by order of packet) the rule is validated
		const mmt_array_t * trace,      //historic messages that validates the rule
		void *user_data                 //#user-data being given in register_security
){
	security_context_t *context = (security_context_t *) user_data;

	//depending on the configuration of security.report-rule-description,
	// we include the description of the rule or not
	const char *description = context->config->is_report_rule_description? rule->description : "";
	const char *exec_trace  = mmt_convert_execution_trace_to_json_string( trace, rule );

	int i;
	struct timeval ts;
	mmt_sec_decode_timeval(timestamp, &ts );

	char message[ MAX_LENGTH_REPORT_MESSAGE ];
	int offset = 0;
	STRING_BUILDER_WITH_SEPARATOR( offset, message, sizeof( message ), ",",
			__INT( rule->id ),
			__STR( verdict_type_string[verdict] ),
			__STR( rule->type_string ),
			__STR( description ), //string with quotes
			__ARR( exec_trace )   //string without quotes
	);

	output_write_report( context->output,
				context->config->output_channels,
				SECURITY_REPORT_TYPE,
				&ts,
				message);

	uint32_t ip_src;
	//when security detect an anomaly ==> redirect all traffic coming from an IP source to lpi
	if( context->lpi ){
		for( i=0; i<rule->events_count; i++ ){
			ip_src = _get_ip_src_from_trace( i, trace );

			//block all trafic ?
			if( ip_src == 0 )
				continue;
			//rember IP in LPI process
			lpi_include_ip( context->lpi, ip_src );
		}
	}
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

#ifdef TCP_REASSEMBLY_MODULE
	//we need the length of tcp session payload
	if( proto_id == PROTO_TCP && att_id == TCP_SESSION_PAYLOAD_UP ){
		if (!register_extraction_attribute( dpi_handler, PROTO_TCP, TCP_SESSION_PAYLOAD_UP_LEN)){
			log_write( LOG_WARNING, "Cannot register protocol/attribute tcp.tcp_session_payload_up_len");
			return false;
		}
		*add_att_id =  TCP_SESSION_PAYLOAD_UP_LEN;
		return true;
	}
	if( proto_id == PROTO_TCP && att_id == TCP_SESSION_PAYLOAD_DOWN ){
		if (!register_extraction_attribute( dpi_handler, PROTO_TCP, TCP_SESSION_PAYLOAD_DOWN_LEN)){
			log_write( LOG_WARNING, "Cannot register protocol/attribute tcp.tcp_session_payload_down_len");
			return false;
		}
		*add_att_id =  TCP_SESSION_PAYLOAD_DOWN_LEN;
		return true;
	}
#endif

	return false;
}

/**
 * Update security parameters
 * @param param_id
 * @param val
 */
static inline void _update_lib_security_param( int param_id, uint32_t val ){
	//if user want to use default value => do nothing
	if( val == 0 )
		return;

	uint32_t old_val = mmt_sec_get_config( param_id );
	//value does not change?
	if( val == old_val )
		return;

	//update the new value
	mmt_sec_set_config( param_id, val );
	log_write( LOG_INFO, "Overridden the security parameter '%s' by %d", mmt_sec_get_config_name( param_id ), val );
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

	//set default parameters for libmmt_security
	_update_lib_security_param( MMT_SEC__CONFIG__INPUT__MAX_MESSAGE_SIZE,  config->lib.input_max_message_size );
	_update_lib_security_param( MMT_SEC__CONFIG__SECURITY__MAX_INSTANCES,  config->lib.security_max_instances );
	_update_lib_security_param( MMT_SEC__CONFIG__SECURITY__SMP__RING_SIZE, config->lib.security_smp_ring_size );

	//init
	security_context_t *ret = mmt_alloc_and_init_zero(sizeof( security_context_t ));
	ret->dpi_handler = dpi_handler;
	ret->config      = config;
	ret->output      = output;
	//init mmt-sec to verify the rules
	ret->sec_handler = mmt_sec_register( threads_count, cores_id, config->rules_mask, verbose, _print_security_verdict, ret );

	if( config->ignore_remain_flow == CONF_SECURITY_IGNORE_REMAIN_FLOW_FROM_SECURITY )
		mmt_sec_set_ignore_remain_flow( ret->sec_handler, true, 5000000 ); //5M flows

	rule_info_t const*const*rules_array;
	ret->rules_count = mmt_sec_get_rules_info( &rules_array );

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

#ifdef TCP_REASSEMBLY_MODULE
		 if( !is_need_tcp_reassembly
				 && ret->proto_atts[i]->proto_id == PROTO_TCP
				 && (ret->proto_atts[i]->att_id == TCP_SESSION_PAYLOAD_UP || ret->proto_atts[i]->att_id == TCP_SESSION_PAYLOAD_DOWN ))
			 	 is_need_tcp_reassembly = true;
#endif
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
