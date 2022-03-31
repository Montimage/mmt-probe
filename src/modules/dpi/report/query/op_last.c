/*
 * op_diff.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op_diff{
	data_types_t data_type;
	bool has_last_value;
	void *result;
	uint16_t count, index;
}op_last_t;

data_types_t op_last_get_data_type( data_types_t data_type ){
	//the result should be the same
	// but for now we support only IPv4
	switch( data_type ){
	case MMT_DATA_IP_ADDR:
		return data_type;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_last_can_handle( data_types_t data_type ){
	return op_last_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_last_reset_value( op_last_t *op ){
	op->has_last_value = false;
}

op_last_t *op_last_create( data_types_t data_type ){
	op_last_t *op = mmt_alloc( sizeof( op_last_t ));
	op->data_type = data_type;
	switch( data_type ){
	case MMT_U8_DATA:
		op->result = mmt_alloc( sizeof(uint8_t));
		break;
	case MMT_U16_DATA:
		op->result = mmt_alloc( sizeof(uint16_t));
		break;
	case MMT_U32_DATA:
	case MMT_DATA_IP_ADDR:
		op->result = mmt_alloc( sizeof(uint32_t));
		break;
	default:
		mmt_probe_free( op );
		return NULL;
	}
	op_last_reset_value( op );
	return op;
}

void op_last_release( op_last_t *op ){
	mmt_probe_free( op );
}

bool op_last_add_data( op_last_t *op, const void* value ){
	switch( op->data_type ){
	//float
	case MMT_DATA_IP_ADDR:
		*(uint16_t *)op->result = *(uint16_t *) value;
		return true;
	default:
		return false;
	}
}

const void* op_last_get_value( op_last_t *op ){
	if( ! op->has_last_value )
		return NULL;
	return op->result;
}
