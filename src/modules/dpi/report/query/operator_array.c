/*
 * operator_array.c
 *
 *  Created on: Apr 11, 2022
 *      Author: nhnghia
 */


#include "operator.h"

bool operator_array_can_handle( query_op_type_t op, data_types_t data_type ){
	switch( data_type ){
	case MMT_U32_ARRAY:
		return query_operator_can_handle( op, MMT_U32_DATA );
	case MMT_U64_ARRAY:
		return query_operator_can_handle( op, MMT_U64_DATA );
	default:
		return false;
	}
}


data_types_t operator_array_get_data_type( query_op_type_t op, data_types_t data_type ){
	return data_type;
}
