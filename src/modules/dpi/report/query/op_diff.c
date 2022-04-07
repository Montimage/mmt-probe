/*
 * op_diff.c
 *
 * Currently diff operator does not take into account the negative number:
 * it requires that the next value must be greater than or equal to the current value
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef union{
	float     f;
	uint8_t   i8;
	uint16_t i16;
	uint32_t i32;
	uint64_t i64;
} value_t;

typedef struct _op_diff{
	data_types_t data_type;
	value_t last_value, result;
	size_t counter;
}op_diff_t;

data_types_t op_diff_get_data_type( data_types_t data_type ){
	//Note: if new data type is supported
	// => you may need to increase data size of last_value and result variables
	//the result should be the same
	switch( data_type ){
	case MMT_DATA_FLOAT:
	case MMT_U8_DATA:
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
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
	op->counter = 0;
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

#define CALCUL_DIFF( type, i )\
		v.i = *(type *) value;                          \
		op->counter ++;                                 \
		if( op->counter > 1 )                           \
		    if( v.i > op->last_value.i)                 \
		        op->result.i = v.i - op->last_value.i;

bool op_diff_add_data( op_diff_t *op, const void* value ){
	value_t v;
	struct timeval t;

	op->result.i64 = 0;

	if( value == NULL )
		return false;

	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		CALCUL_DIFF( float, f);
		break;
	case MMT_U8_DATA:
		CALCUL_DIFF( uint8_t, i8);
		break;
	case MMT_U16_DATA:
		CALCUL_DIFF( uint16_t, i16);
		break;
	case MMT_U32_DATA:
		CALCUL_DIFF( uint32_t, i32);
		break;
	case MMT_U64_DATA:
		CALCUL_DIFF( uint64_t, i64);
		break;
	case MMT_DATA_TIMEVAL:
		t = *(struct timeval *) value;
		// a float cannot contain this value, we need an uint64_t
		//convert timeval to microsecond
		v.i64 = t.tv_sec * 1000000 + t.tv_usec;
		value = &v;
		CALCUL_DIFF( uint64_t, i64);
		break;
	default:
		return false;
	}
	op->last_value = v;
	return true;
}

const void* op_diff_get_value( op_diff_t *op ){
	if( op->counter > 1)
		return & op->result;
	return NULL;
}
