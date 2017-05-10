/*
 * security.c
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */


#include "security.h"

#include <mmt_smp_security.h>
#include <dpi_message_t.h>

#include <tcpip/mmt_tcpip.h>
#include <signal.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

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
	message_t *msg = create_message_t( proto_atts_count );
	msg->timestamp = mmt_sec_encode_timeval( &pkt->p_hdr->ts );
	msg->counter   = pkt->packet_id;

	//get a list of proto/attributes being used by mmt-security
	for( i=0; i<proto_atts_count; i++ ){
		dpi_message_set_data( pkt, proto_atts[i]->dpi_type, msg, proto_atts[i]->proto_id, proto_atts[i]->att_id );
	}

	return msg;
}

/**
 * This function is called by mmt-dpi for each incoming packet containing registered proto/att.
 * It gets interested information from the #ipkacet to a message then sends the
 * message to mmt-security.
 */
static int _packet_handler( const ipacket_t *ipacket, void *args ) {
	sec_wrapper_t *wrapper = (sec_wrapper_t *)args;

	message_t *msg = _get_packet_info( ipacket, wrapper->proto_atts, wrapper->proto_atts_count );

	//if there is no interested information
	//TODO: to check if we still need to send timestamp/counter to mmt-sec?
	if( unlikely( msg->elements_count == 0 )){
		free_message_t( msg );
		return 0;
	}

	mmt_sec_process( wrapper->sec_handler, msg );
	wrapper->msg_count ++;

	return 0;
}

static void _signal_handler_seg(int signal_type) {
	mmt_error( "Interrupted by signal %d", signal_type );
	mmt_print_execution_trace();
	exit( 1 );
}

/**
 * This function inits security rules
 * @return
 */
int init_security(){

	signal(SIGSEGV, _signal_handler_seg );
	//exclude rules in rules_mask
	return mmt_sec_init( get_probe_context_config()->security2_excluded_rules );
}


void close_security(){
	mmt_sec_close();
}

/**
 * A function to be called when a rule is validated
 * Note: this function can be called from one or many different threads,
 *       ==> be carefully when using static or global variables inside it
 */
void security_print_verdict(
		const rule_info_t *rule,		//rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,					//moment (by order of packet) the rule is validated
		const mmt_array_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in register_security
)
{
	const char *description = rule->description;
	const char *exec_trace  = mmt_convert_execution_trace_to_json_string( trace, rule );
	char message[10000];
	int len = 10000;
	const mmt_probe_context_t * mmt_conf = get_probe_context_config();
	struct smp_thread *th = (struct smp_thread *) user_data;

	len = snprintf( message, len, "%d,%d,\"%s\",%ld,%"PRIu32",\"%s\",\"%s\",\"%s\",%s",
			MMT_SECURITY_REPORT_FORMAT,
			mmt_conf->probe_id_number,
			mmt_conf->input_source,
			time( NULL ),
			rule->id,
			verdict_type_string[verdict],
			rule->type_string,
			description,
			exec_trace );

	message[ len ] = '\0';

	if( mmt_conf->output_to_file_enable && mmt_conf->security2_output_channel[0])
		send_message_to_file_thread ( message, user_data );
	if ( mmt_conf->redis_enable && mmt_conf->security2_output_channel[1])
		send_message_to_redis ( "security.report", message );
	if ( mmt_conf->kafka_enable && mmt_conf->security2_output_channel[2])
		send_msg_to_kafka( mmt_conf->topic_object->rkt_security, message );

	//	printf("%s", message );
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
sec_wrapper_t* register_security( mmt_handler_t *dpi_handler, size_t threads_count,
		const uint32_t *cores_id, const char *rules_mask,
		bool verbose, mmt_sec_callback callback, struct smp_thread *th ){

	sec_wrapper_t *ret = mmt_mem_alloc(sizeof( sec_wrapper_t ));

	int i;
	char att_registed[10000], *att_registed_ptr = att_registed;


	ret->threads_count = threads_count;
	ret->msg_count     = 0;

	//init mmt-sec to verify the rules
	ret->sec_handler = mmt_sec_register( threads_count, cores_id, rules_mask, verbose, callback, th );

	//register protocols and their attributes using by mmt-sec
	ret->proto_atts_count =  mmt_sec_get_unique_protocol_attributes( & ret->proto_atts );

	for( i=0; i<ret->proto_atts_count; i++ ){
		//mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		if( register_extraction_attribute( dpi_handler, ret->proto_atts[i]->proto_id, ret->proto_atts[i]->att_id ) == 0){
			mmt_warn( "Cannot register protocol/attribute %s.%s", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );
		}
		else
			att_registed_ptr += sprintf( att_registed_ptr, "%s.%s,", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );

		//we need IP_HEADER_LEN to calculate length of IP_OPTS
		if( ret->proto_atts[i]->proto_id == PROTO_IP && ret->proto_atts[i]->att_id == IP_OPTS ){
			if (!register_extraction_attribute( dpi_handler, PROTO_IP, IP_HEADER_LEN)){
				mmt_warn("Cannot register protocol/attribute ip.header_len");
			}
			else
				att_registed_ptr += sprintf( att_registed_ptr, "ip.header_len");
		}

	}
	if( verbose ){
		//replace the last comma by dot
		att_registed[ strlen( att_registed ) - 1 ] = '.';
		mmt_info( "Registered %d proto.atts: %s", ret->proto_atts_count, att_registed );
	}

	//Register a packet handler, it will be called for every processed packet
	register_packet_handler( dpi_handler, 10, _packet_handler, ret );

	return ret;
}


/**
 * Stop and free mmt_security
 * @param wrapper
 * @return
 */
size_t unregister_security( sec_wrapper_t* ret ){
	size_t alerts_count = 0;

	if( unlikely( ret == NULL || ret->sec_handler == NULL ) )
		return 0;

	alerts_count = mmt_sec_unregister( ret->sec_handler );

	ret->sec_handler = NULL;
	mmt_mem_free( ret );

	return alerts_count;
}
