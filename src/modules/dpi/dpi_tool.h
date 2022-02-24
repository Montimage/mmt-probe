/*
 * dpi_tool.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 *  Collection of functions for registering or unregistering for MMT-DPI some attributes to extract
 */

#ifndef SRC_MODULES_DPI_DPI_TOOL_H_
#define SRC_MODULES_DPI_DPI_TOOL_H_

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdint.h>
#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include "../../configure.h"
#include "../../lib/string_builder.h"
#include "../../lib/memory.h"
#include "../../lib/inet.h"

/**
 * Get the last protocol ID on the current protocol hierarchy of the session
 * @param dpi_session
 * @return
 */
static inline uint32_t dpi_get_proto_id_from_session( const mmt_session_t * dpi_session ){
	const proto_hierarchy_t *proto_hierarchy = get_session_protocol_hierarchy( dpi_session );
	return proto_hierarchy->proto_path[ proto_hierarchy->len - 1 ];
}

/**
 * Get protocol and attribute IDs from their names
 * @param att
 * @param proto_id
 * @param att_id
 * @return
 */
static inline bool dpi_load_proto_id_and_att_id( dpi_protocol_attribute_t *att ){
	att->proto_id = get_protocol_id_by_name( att->proto_name );
	if( att->proto_id != 0 )
		att->attribute_id = get_attribute_id_by_protocol_id_and_attribute_name( att->proto_id, att->attribute_name );
	return att->proto_id != 0 && att->attribute_id != 0;
}

/**
 * Register a list of protocols and attributes to DPI
 * @param atts
 * @param count
 * @param dpi_handler
 * @param handler_fct
 * @param args
 * @return
 */
static inline int dpi_register_attribute( dpi_protocol_attribute_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct, void *args ){
	int i, ret = 0;
	for( i=0; i<count; i++ ){
		if( ! dpi_load_proto_id_and_att_id( &atts[i] ) ){
			log_write( LOG_ERR, "Does not support protocol [%s] with its attribute [%s]",
					atts[i].proto_name,
					atts[i].attribute_name);
			continue;
		}

		//register without handler function
		if( handler_fct == NULL ){
			if( ! register_extraction_attribute( dpi_handler, atts[i].proto_id, atts[i].attribute_id) )
				log_write( LOG_WARNING, "Cannot register attribute [%s.%s]",
						atts[i].proto_name,
						atts[i].attribute_name
				);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler, atts[i].proto_id, atts[i].attribute_id, handler_fct, NULL, args ) ){
				log_write( LOG_ERR, "Cannot register handler for [%s.%s]",
						atts[i].proto_name,
						atts[i].attribute_name );
			}
			else
				ret ++;
		}
	}
	return ret;
}

/**
 * Unregister
 * @param atts
 * @param count
 * @param dpi_handler
 * @param handler_fct
 * @return
 */
static inline int dpi_unregister_attribute( const dpi_protocol_attribute_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct ){
	int i, ret = 0;
	uint32_t proto_id, att_id;
	for( i=0; i<count; i++ ){
		proto_id = atts[i].proto_id;
		att_id   = atts[i].attribute_id;
		if( proto_id == 0 || att_id == 0 )
			continue;

		//register without handler function
		if( handler_fct == NULL ){
			if( is_registered_attribute( dpi_handler, proto_id, att_id) ){
				if( ! unregister_extraction_attribute( dpi_handler, proto_id, att_id) )
					log_write( LOG_WARNING, "Cannot unregister attribute [%s.%s]",
							atts[i].proto_name,
							atts[i].attribute_name
					);
			else
				ret ++;
			}
		}else{
			if( is_registered_attribute_handler( dpi_handler, proto_id, att_id, handler_fct ) ){
				if( !unregister_attribute_handler( dpi_handler, proto_id, att_id, handler_fct))
					log_write( LOG_ERR, "Cannot register handler for [%s.%s]",
						atts[i].proto_name,
						atts[i].attribute_name );
			else
				ret ++;
			}
		}
	}
	return ret;
}

/**
 * Convert protocol hierarchy to a string, e.g., 99.178
 * @param proto_hierarchy
 * @param dest
 * @param max_length
 * @return
 */
static inline int dpi_proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest, int max_length ) {
	int offset = 0;
	int index = 1;
	if (proto_hierarchy->len >= 1) {
		offset += append_number(dest, max_length - offset, proto_hierarchy->proto_path[index]);
		index++;
		for (; index < proto_hierarchy->len; index++) {
			offset += append_char(  dest+offset, max_length - offset, '.');
			offset += append_number(dest+offset, max_length - offset, proto_hierarchy->proto_path[index]);
		}
	}

	dest[ offset ] = '\0';

	return offset;
}

/**
 * Copy string value of a mmt_header_line_t.
 * The function also replace invalid-json-string characters by dots
 * @param target
 * @param target_size
 * @param val
 * @return
 */
static inline bool dpi_copy_string_value( char *target, size_t target_size, mmt_header_line_t *val ){
	if( val == NULL || val->len == 0 ){
		target[0] = '\0';
		return false;
	}

	//length of string + 1 byte for '\0'
	if( val->len + 1 < target_size )
		target_size = val->len + 1;

	int i;
	//copy to target string. Ensure the target is a valid JSON string
	for( i=0; i<target_size; i++ ){
		switch( val->ptr[ i ] ){
		case '\b': //  Backspace (ascii code 08)
		case '\f': //  Form feed (ascii code 0C)
		case '\n': //  New line
		case '\r': //  Carriage return
		case '\t': //  Tab
		case '\\': //  Backslash character
			target[i] = '.';
			break;
		case '"': //  Double quote
			target[i] = '\'';
			break;
		default:
			target[i] = val->ptr[i];
		}
	}
	target[ target_size - 1 ] = '\0';

	return true;
}


typedef struct conditional_handler_struct{
	uint32_t proto_id;
	uint32_t att_id;
	attribute_handler_function handler;
}conditional_handler_t;



/* This function registers attributes and attribute handlers for different condition_reports (if enabled in a configuration file).
 * */
static inline int dpi_register_conditional_handler( mmt_handler_t *dpi_handler, size_t count, const conditional_handler_t *handlers, void *user_argv ) {
	int i, ret = 0;
	const conditional_handler_t *handler;

	for( i=0; i<count; i++ ){
		handler = &handlers[i];

		//register without handler function
		if( handler->handler == NULL ){
			if( ! register_extraction_attribute( dpi_handler, handler->proto_id, handler->att_id) )
				log_write( LOG_WARNING, "Cannot register attribute [%u.%u]",
						handler->proto_id, handler->att_id	);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler,  handler->proto_id, handler->att_id, handler->handler, NULL, user_argv ) )
				log_write( LOG_ERR, "Cannot register handler for [%u.%u]",
						handler->proto_id, handler->att_id );
			else
				ret ++;
		}
	}
	return ret;
}

static inline int dpi_unregister_conditional_handler( mmt_handler_t *dpi_handler, size_t count, const conditional_handler_t *handlers) {
	int i, ret = 0;
	const conditional_handler_t *handler;

	for( i=0; i<count; i++ ){
		handler = &handlers[i];

		//register without handler function
		if( handler->handler == NULL ){
			if( !unregister_extraction_attribute( dpi_handler, handler->proto_id, handler->att_id) )
				log_write( LOG_WARNING, "Cannot register attribute [%u.%u]",
						handler->proto_id, handler->att_id	);
			else
				ret ++;
		}else{
			if( !unregister_attribute_handler( dpi_handler,  handler->proto_id, handler->att_id, handler->handler ) )
				log_write( LOG_ERR, "Cannot register handler for [%u.%u]",
						handler->proto_id, handler->att_id );
			else
				ret ++;
		}
	}
	return ret;
}


typedef struct{
	bool is_ipv4;
	union {
		uint32_t ipv4;
		uint8_t ipv6[16];
	};
}mmt_ip_t;

static inline bool dpi_get_ip_from_packet( const ipacket_t *ipacket, mmt_ip_t *ip_src, mmt_ip_t *ip_dst ){

	mmt_session_t * dpi_session = ipacket->session;
	if( unlikely( dpi_session == NULL))
		return false;

	//the index in the protocol hierarchy of the protocol \session belongs to
	const uint32_t proto_session_index  = get_session_protocol_index( dpi_session );
	// Flow extraction
	const uint32_t proto_session_id = get_protocol_id_at_index(ipacket, proto_session_index);

	//must be either PROTO_IP or PROTO_IPV6
	if( unlikely( proto_session_id != PROTO_IP && proto_session_id != PROTO_IPV6 )){
		DEBUG("session of packet %lu is not on top of IP nor IPv6, but %d", ipacket->packet_id, proto_session_id );
		return NULL;
	}

	const bool is_session_over_ipv4 = (proto_session_id == PROTO_IP);


	//IPV4
	if (likely( is_session_over_ipv4 )) {

		ip_src->is_ipv4 = ip_dst->is_ipv4 = true;

		uint32_t * src = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_SRC, proto_session_index);
		uint32_t * dst = (uint32_t *) get_attribute_extracted_data_at_index(ipacket, PROTO_IP, IP_DST, proto_session_index);

		if (likely( src ))
			ip_src->ipv4 = *src;

		if (likely( dst ))
			ip_dst->ipv4 = (*dst);
	} else {
		ip_src->is_ipv4 = ip_dst->is_ipv4 = false;
		void * src = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_SRC, proto_session_index);
		void * dst = (void *) get_attribute_extracted_data_at_index(ipacket, PROTO_IPV6, IP6_DST, proto_session_index);
		if (likely( src ))
			assign_16bytes( &ip_src->ipv6, src);
		if (likely( dst ))
			assign_16bytes( &ip_dst->ipv6, dst);
	}

	return true;
}


static inline bool dpi_get_ip_string_from_packet( const ipacket_t *ipacket, char *ip_src_string, char *ip_dst_string ){
	mmt_ip_t ip_src, ip_dst;
	if( !(dpi_get_ip_from_packet( ipacket, &ip_src, &ip_dst)) )
		return false;

	if( ip_src.is_ipv4 ){
		inet_ntop4( ip_src.ipv4, ip_src_string );
		inet_ntop4( ip_dst.ipv4, ip_dst_string );
	}else{
		inet_ntop( AF_INET6, &ip_src.ipv6, ip_src_string, INET6_ADDRSTRLEN );
		inet_ntop( AF_INET6, &ip_dst.ipv6, ip_dst_string, INET6_ADDRSTRLEN );
	}
	return true;
}
#endif /* SRC_MODULES_DPI_DPI_TOOL_H_ */
