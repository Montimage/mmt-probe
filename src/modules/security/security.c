/*
 * security.c
 *
 *  Created on: Mar 17, 2017
 *  Created by: Huu Nghia NGUYEN <huunghia.nguyen@montimage.com>
 */

#include "security.h"

#include <dpi_message_t.h>
#include <tcpip/mmt_tcpip.h>
#include <signal.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>

#include "../output/output.h"

#define SECURITY_DPI_PACKET_HANDLER_ID 10

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
	wrapper->msg_count ++;

	return 0;
}

/**
 * This function inits security rules
 * @return
 */
int security_open( const char *excluded_rules ){
	log_write( LOG_INFO, "start MMT-Security %s", mmt_sec_get_version_info() );
	//exclude rules in rules_mask
	return mmt_sec_init( excluded_rules );
}


void security_close(){
	mmt_sec_close();
}

/**
 * A function to be called when a rule is validated
 * Note: this function can be called from one or many different threads,
 *       ==> be carefully when using static or global variables inside it
 */
static void _print_verdict(
		const rule_info_t *rule,		    //rule being validated
		enum verdict_type verdict,		//DETECTED, NOT_RESPECTED
		uint64_t timestamp,  			//moment (by time) the rule is validated
		uint64_t counter,			    //moment (by order of packet) the rule is validated
		const mmt_array_t * const trace,//historic of messages that validates the rule
		void *user_data					//#user-data being given in register_security
)
{
	const char *description = rule->description;
	const char *exec_trace  = mmt_convert_execution_trace_to_json_string( trace, rule );
	char message[10000];
	int len = 10000;
	worker_context_t *worker_context = (worker_context_t *) user_data;

	struct timeval ts;
	mmt_sec_decode_timeval(timestamp, &ts );

	output_write_report(worker_context->output,
			& worker_context->probe_context->config->reports.security->output_channels,
			SECURITY_REPORT_TYPE,
			&ts,
			"%"PRIu32",\"%s\",\"%s\",\"%s\",%s",
			rule->id,
			verdict_type_string[verdict],
			rule->type_string,
			description,
			exec_trace
			);
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
security_context_t* security_worker_alloc_init( worker_context_t *worker ){
	mmt_handler_t *dpi_handler = worker->dpi_handler;
	size_t threads_count = worker->probe_context->config->reports.security->threads_size;
	const uint32_t *cores_id = (uint32_t[]){0,1};
	const char *rules_mask = worker->probe_context->config->reports.security->rules_mask;
	const bool verbose = (worker->index == 0); //
	int i;

	int att_registed_offset = 0;
	const int att_registed_length = 10000;
	char att_registed[10000];

	if( ! worker->probe_context->config->reports.security->is_enable )
		return NULL;

	//init
	security_context_t *ret = alloc(sizeof( security_context_t ));

	ret->worker_context = worker;
	ret->threads_count  = threads_count;
	ret->msg_count      = 0;

	//init mmt-sec to verify the rules
	ret->sec_handler = mmt_sec_register( threads_count, cores_id, rules_mask, false, _print_verdict, worker );

	//register protocols and their attributes using by mmt-sec
	ret->proto_atts_count =  mmt_sec_get_unique_protocol_attributes((void*) &ret->proto_atts );

	for( i=0; i<ret->proto_atts_count; i++ ){
		//mmt_debug( "Registered attribute to extract: %s.%s", proto_atts[i]->proto, proto_atts[i]->att );
		if( register_extraction_attribute( dpi_handler, ret->proto_atts[i]->proto_id, ret->proto_atts[i]->att_id ) == 0){
			log_write( LOG_WARNING, "Cannot register protocol/attribute %s.%s", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );
		}
		else if( verbose )
			att_registed_offset += snprintf( att_registed + att_registed_offset, MAX( att_registed_length - att_registed_offset, 0),
					"%s.%s,", ret->proto_atts[i]->proto, ret->proto_atts[i]->att );

		//we need IP_HEADER_LEN to calculate length of IP_OPTS
		if( ret->proto_atts[i]->proto_id == PROTO_IP && ret->proto_atts[i]->att_id == IP_OPTS ){
			if (!register_extraction_attribute( dpi_handler, PROTO_IP, IP_HEADER_LEN)){
				log_write( LOG_WARNING, "Cannot register protocol/attribute ip.header_len");
			}
			else if( verbose )
				att_registed_offset += snprintf( att_registed + att_registed_offset, MAX( att_registed_length - att_registed_offset, 0),
						"ip.header_len");
		}

	}
	if( verbose ){
		rule_info_t const* const* rules_array = NULL;
		//remove the last comma
		att_registed[ strlen( att_registed ) - 1 ] = '\0';
		log_write( LOG_INFO,"Registered %d proto.atts to process %zu rules: %s",
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

	log_write( LOG_INFO, "Security on worker %d processed %zu messages, generated %zu alerts", ret->worker_context->index, ret->msg_count, alerts_count );

	ret->sec_handler = NULL;

	unregister_packet_handler (ret->worker_context->dpi_handler, SECURITY_DPI_PACKET_HANDLER_ID );
	xfree( ret );

	return alerts_count;
}
