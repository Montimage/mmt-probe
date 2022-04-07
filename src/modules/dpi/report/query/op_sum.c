/*
 * op_sump.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op_sum{
	data_types_t data_type;
	union{
		uint64_t i;
		float    f;
	} total;
}op_sum_t;

data_types_t op_sum_get_data_type( data_types_t data_type ){
	//depending on input data type, the output data type may be either uint64_t or float
	switch( data_type ){
	case MMT_DATA_FLOAT:
		return MMT_DATA_FLOAT;
	case MMT_U8_DATA:
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
		return MMT_U64_DATA;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_sum_can_handle( data_types_t data_type ){
	return op_sum_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_sum_reset_value( op_sum_t *op ){
	op->total.i = 0;
	op->total.f = 0;
}

op_sum_t *op_sum_create( data_types_t data_type ){
	op_sum_t *op = mmt_alloc( sizeof( op_sum_t ));
	op->data_type = data_type;
	op_sum_reset_value( op );
	return op;
}

void op_sum_release( op_sum_t *op ){
	mmt_probe_free( op );
}

bool op_sum_add_data( op_sum_t *op, const void* value ){
	if( value == NULL )
		return false;
	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		op->total.f += *(float *) value;
		return true;
	//integer
	case MMT_U8_DATA:
		op->total.i += *(uint8_t *) value;
		return true;
	case MMT_U16_DATA:
		op->total.i += *(uint16_t *) value;
		return true;
	case MMT_U32_DATA:
		op->total.i += *(uint32_t *) value;
		return true;
	case MMT_U64_DATA:
		op->total.i += *(uint64_t *) value;
		return true;
	default:
		return false;
	}

	return true;
}

const void* op_sum_get_value( op_sum_t *op ){
	data_types_t type = op_sum_get_data_type( op->data_type );
	switch( type ){
	case MMT_U64_DATA:
		return & op->total.i;
	case MMT_DATA_FLOAT:
		return & op->total.f;
	default:
		return NULL;
	}
}
