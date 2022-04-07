/*
 * op_avg.c
 *
 *  Created on: Mar 31, 2022
 *      Author: nhnghia
 */


#include "operator.h"

typedef struct _op_avg{
	data_types_t data_type;
	uint64_t counter;
	union{
		float f;
		size_t i;
	} total;
	float result;
}op_avg_t;

data_types_t op_avg_get_data_type( data_types_t data_type ){
	//the result will be a float number
	switch( data_type ){
	case MMT_DATA_FLOAT:
	case MMT_U8_DATA:
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
		return MMT_DATA_FLOAT;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_avg_can_handle( data_types_t data_type ){
	return op_avg_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_avg_reset_value( op_avg_t *op ){
	op->total.i = 0;
	op->total.f = 0;
	op->counter = 0;
	op->result  = 0;
}

op_avg_t *op_avg_create( data_types_t data_type ){
	op_avg_t *op = mmt_alloc( sizeof( op_avg_t ));
	op->data_type = data_type;
	op_avg_reset_value( op );
	return op;
}

void op_avg_release( op_avg_t *op ){
	mmt_probe_free( op );
}

bool op_avg_add_data( op_avg_t *op, const void* value ){
	if( value == NULL )
		return false;
	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		op->total.f += *(float *) value;
		break;
	//integer
	case MMT_U8_DATA:
		op->total.i += *(uint8_t *) value;
		break;
	case MMT_U16_DATA:
		op->total.i += *(uint16_t *) value;
		break;
	case MMT_U32_DATA:
		op->total.i += *(uint32_t *) value;
		break;
	case MMT_U64_DATA:
		op->total.i += *(uint64_t *) value;
		break;
	default:
		return false;
	}
	op->counter ++;
	return true;
}

const void* op_avg_get_value( op_avg_t *op ){
	if( op->counter != 0 ){
		if( op->data_type == MMT_DATA_FLOAT )
			op->result = op->total.f / op->counter;
		else
			op->result = op->total.i * 1.0/ op->counter;
	} else
		op->result = 0;
	return &op->result;
}
