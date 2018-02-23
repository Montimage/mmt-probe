/*
 * dpi_tool.h
 *
 *  Created on: Dec 19, 2017
 *          by: Huu Nghia
 */

#ifndef SRC_MODULES_DPI_DPI_TOOL_H_
#define SRC_MODULES_DPI_DPI_TOOL_H_

#include <mmt_core.h>
#include "../../lib/alloc.h"
#include "../../lib/configure.h"

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
			log_write( LOG_ERR, "Does not support protocol %s and its attribute %s",
					atts[i].proto_name,
					atts[i].attribute_name);
			continue;
		}

		//register without handler function
		if( handler_fct == NULL ){
			if( ! register_extraction_attribute( dpi_handler, proto_id, att_id) )
				log_write( LOG_WARNING, "Cannot register attribute %s.%s",
						atts[i].proto_name,
						atts[i].attribute_name
				);
			else
				ret ++;
		}else{
			if( !register_attribute_handler( dpi_handler, proto_id, att_id, handler_fct, NULL, args ) ){
				log_write( LOG_ERR, "Cannot register handler for %s.%s",
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
			log_write( LOG_ERR, "Does not support protocol %s and its attribute %s",
					atts[i].proto_name,
					atts[i].attribute_name);
			continue;
		}

		//register without handler function
		if( handler_fct == NULL ){
			if( is_registered_attribute( dpi_handler, proto_id, att_id) ){
				if( ! unregister_extraction_attribute( dpi_handler, proto_id, att_id) )
					log_write( LOG_WARNING, "Cannot unregister attribute %s.%s",
							atts[i].proto_name,
							atts[i].attribute_name
					);
			else
				ret ++;
			}
		}else{
			if( is_registered_attribute_handler( dpi_handler, proto_id, att_id, handler_fct ) ){
				if( !unregister_attribute_handler( dpi_handler, proto_id, att_id, handler_fct))
					log_write( LOG_ERR, "Cannot register handler for %s.%s",
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
	if (proto_hierarchy->len >= 1) {
		int index = 1;
		offset += snprintf(dest, max_length - offset, "%u", proto_hierarchy->proto_path[index]);
		index++;
		for (; index < proto_hierarchy->len && index < 16; index++) {
			offset += snprintf(&dest[offset], max_length - offset, ".%u", proto_hierarchy->proto_path[index]);
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

	if( val->len < target_size )
		target_size = val->len;

	memcpy( target, val->ptr, target_size );
	target[ target_size ] = '\0';

	return true;
}

#endif /* SRC_MODULES_DPI_DPI_TOOL_H_ */
