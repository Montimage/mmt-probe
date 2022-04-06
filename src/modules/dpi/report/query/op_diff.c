/*
 * op_diff.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op_diff{
	data_types_t data_type;
	float last_value;
	float result;
	size_t counter;
}op_diff_t;

data_types_t op_diff_get_data_type( data_types_t data_type ){
	//the result should be the same
	switch( data_type ){
	case MMT_DATA_FLOAT:
	case MMT_U8_DATA:
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
	case MMT_DATA_TIMEVAL:
		return MMT_DATA_FLOAT;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_diff_can_handle( data_types_t data_type ){
	return op_diff_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_diff_reset_value( op_diff_t *op ){
	op->counter = 0;
	op->result  = 0;
	op->result  = 0;
}

op_diff_t *op_diff_create( data_types_t data_type ){
	op_diff_t *op = mmt_alloc( sizeof( op_diff_t ));
	op->data_type = data_type;
	op_diff_reset_value( op );
	return op;
}

void op_diff_release( op_diff_t *op ){
	mmt_probe_free( op );
}

bool op_diff_add_data( op_diff_t *op, const void* value ){
	float f;
	struct timeval t;

	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		f = *(float *) value;
		break;
	case MMT_U8_DATA:
		f = *(uint8_t *) value;
		break;
	case MMT_U16_DATA:
		f = *(uint16_t *) value;
		break;
	case MMT_U32_DATA:
		f = *(uint32_t *) value;
		break;
	case MMT_U64_DATA:
		f = *(uint64_t *) value;
		break;
	case MMT_DATA_TIMEVAL:
		t = *(struct timeval *) value;
		//convert timeval to microsecond
		f = t.tv_sec * 1000000 + t.tv_usec;
		break;
	default:
		return false;
	}
	op->counter ++;

	if( op->counter > 1 )
		op->result = f - op->last_value;
	op->last_value = f;
	return true;
}

const void* op_diff_get_value( op_diff_t *op ){
	if( op->counter > 1)
		return & op->result;
	return NULL;
}
