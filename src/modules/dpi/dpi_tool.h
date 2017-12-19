/*
 * dpi_tool.h
 *
 *  Created on: Dec 19, 2017
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_DPI_TOOL_H_
#define SRC_MODULES_DPI_DPI_TOOL_H_

#include <mmt_core.h>
#include "../../lib/configure.h"

static inline bool dpi_get_proto_id_and_att_id( const dpi_protocol_attribute_t *att, uint32_t *proto_id, uint32_t *att_id ){
	*proto_id = get_protocol_id_by_name( att->proto_name );
	if( *proto_id != 0 )
		*att_id = get_attribute_id_by_protocol_id_and_attribute_name( *proto_id, att->attribute_name );
	else
		*att_id = 0;
	return *proto_id != 0 && *att_id != 0;
}

#endif /* SRC_MODULES_DPI_DPI_TOOL_H_ */
