/*
 * dpi_tool.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 *  Collection of functions for registering or unregistering for MMT-DPI some attributes to extract
 */

#ifndef SRC_MODULES_DPI_DPI_TOOL_H_
#define SRC_MODULES_DPI_DPI_TOOL_H_

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include "../../configure.h"
#include "../../lib/memory.h"
#include "../../lib/string_builder.h"

static inline uint32_t dpi_get_proto_id_from_session( const mmt_session_t * dpi_session ){
	const proto_hierarchy_t *proto_hierarchy = get_session_protocol_hierarchy( dpi_session );
	int len = proto_hierarchy->len;
	if( unlikely( len > 16 ))
		len = 16;
	return proto_hierarchy->proto_path[ len - 1 ];
}

static inline bool dpi_get_proto_id_and_att_id( const dpi_protocol_attribute_t *att, uint32_t *proto_id, uint32_t *att_id ){
	*proto_id = get_protocol_id_by_name( att->proto_name );
	if( *proto_id != 0 )
		*att_id = get_attribute_id_by_protocol_id_and_attribute_name( *proto_id, att->attribute_name );
	else
		*att_id = 0;
	return *proto_id != 0 && *att_id != 0;
}


static inline int dpi_register_attribute( const dpi_protocol_attribute_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct, void *args ){
	int i, ret = 0;
	uint32_t proto_id, att_id;
	for( i=0; i<count; i++ ){
		if( ! dpi_get_proto_id_and_att_id( &atts[i], &proto_id, &att_id ) ){
			log_write( LOG_ERR, "Does not support protocol [%s] with its attribute [%s]",
					atts[i].proto_name,
					atts[i].attribute_name);
			continue;
		}

		//register without handler function
		if( handler_fct == NULL ){
			if( ! register_extraction_attribute( dpi_handler, proto_id, att_id) )
				log_write( LOG_WARNING, "Cannot register attribute [%s.%s]",
						atts[i].proto_name,
						atts[i].attribute_name
				);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler, proto_id, att_id, handler_fct, NULL, args ) ){
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


static inline int dpi_unregister_attribute( const dpi_protocol_attribute_t *atts, size_t count,
	mmt_handler_t *dpi_handler, attribute_handler_function handler_fct ){
	int i, ret = 0;
	uint32_t proto_id, att_id;
	for( i=0; i<count; i++ ){
		if( ! dpi_get_proto_id_and_att_id( &atts[i], &proto_id, &att_id ) ){
			log_write( LOG_ERR, "Does not support protocol [%s] width its attribute [%s]",
					atts[i].proto_name,
					atts[i].attribute_name);
			continue;
		}

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


static inline int dpi_proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest, int max_length ) {
	int offset = 0;
	int index = 1;
	if (proto_hierarchy->len >= 1) {
		offset += append_number(dest, max_length - offset, proto_hierarchy->proto_path[index]);
		index++;
		for (; index < proto_hierarchy->len && index < 16; index++) {
			offset += append_char(  dest+offset, max_length - offset, '.');
			offset += append_number(dest+offset, max_length - offset, proto_hierarchy->proto_path[index]);
		}
	}

	dest[ offset ] = '\0';

	return offset;
}

/**
 * Copy string value of a mmt_header_line_t
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
		case '\\': //  Backslash characte
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
#endif /* SRC_MODULES_DPI_DPI_TOOL_H_ */
