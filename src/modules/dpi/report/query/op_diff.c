/*
 * op_diff.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op_diff{
	data_types_t data_type;
	union {
		float          f;
		uint64_t       i;
	} last_value; //store the 2 latest 2 values
	bool has_last_value;
	union {
		float    f;
		uint64_t i;
	} result;
	uint16_t count, index;
}op_diff_t;

data_types_t op_diff_get_data_type( data_types_t data_type ){
	//the result should be the same
	switch( data_type ){
	case MMT_DATA_FLOAT:
		return data_type;
	case MMT_DATA_TIMEVAL:
		return MMT_U64_DATA;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_diff_can_handle( data_types_t data_type ){
	return op_diff_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_diff_reset_value( op_diff_t *op ){
	op->has_last_value = false;
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
	uint64_t usec;
	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		f = *(float *) value;
		if( op->has_last_value )
			op->result.f = f - op->last_value.f;
		op->last_value.f = f;
		op->has_last_value = true;
		return true;

	//integer
	case MMT_DATA_TIMEVAL:
		t = *(struct timeval *) value;
		//convert timeval to microsecond
		usec = t.tv_sec * 1000000 + t.tv_usec;
		if( op->has_last_value )
			op->result.i = usec - op->last_value.i;

		op->last_value.i = usec;
		op->has_last_value = true;
		return true;
	default:
		return false;
	}
}

const void* op_diff_get_value( op_diff_t *op ){
	if( ! op->has_last_value )
		return NULL;

	data_types_t type = op_diff_get_data_type( op->data_type );
	switch( type ){
	case MMT_U64_DATA:
		return & op->result.f;
	case MMT_DATA_FLOAT:
		return & op->result.i;
	default:
		return NULL;
	}
}
