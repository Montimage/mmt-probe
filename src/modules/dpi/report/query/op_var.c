/*
 * op_var.c
 *
 *  Created on: Mar 31, 2022
 *      Author: nhnghia
 */


#include "operator.h"

#define ELEMENTS_SIZE 500000

typedef struct _op_var{
	data_types_t data_type;
	uint32_t counter;
	uint32_t elements_size; //number of elements
	uint32_t data_size; //memory size of one element
	uint8_t *elements;
	union {
		float    f;
		uint64_t i;
	} result;
}op_var_t;

data_types_t op_var_get_data_type( data_types_t data_type ){
	//the result will be a float number
	switch( data_type ){
	case MMT_DATA_FLOAT:
	case MMT_U8_DATA:
		return MMT_DATA_FLOAT;
	//a bigger number => we round the result into an integer
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
		return MMT_U64_DATA;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_var_can_handle( data_types_t data_type ){
	return op_var_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_var_reset_value( op_var_t *op ){
	op->counter = 0;
}

op_var_t *op_var_create( data_types_t data_type ){
	op_var_t *op;
	if( ! op_var_can_handle( data_type) )
		return NULL;
	op = mmt_alloc( sizeof( op_var_t ));
	op->data_type     = data_type;
	op->elements_size = ELEMENTS_SIZE;
	op->data_size     = get_data_size_by_data_type(data_type);
	op->elements      = mmt_alloc_and_init_zero( op->elements_size * op->data_size );

	op_var_reset_value( op );
	return op;
}

void op_var_release( op_var_t *op ){
	if( op )
		mmt_probe_free( op->elements );
	mmt_probe_free( op );
}


bool op_var_add_data( op_var_t *op, const void* value ){
	size_t index;
	//table is full
	if( op->counter >= op->elements_size || value == NULL)
		return false;

	index = op->counter * op->data_size;
	memcpy( &op->elements[index], value, op->data_size );
	op->counter ++;

	return true;
}

//calculate a var is performed in 2 steps:
// 1. calculate average of elements
// 2.
#define CALCUL_var( type, att )\
		total = 0;                                                   \
		for( i=0; i<op->counter; i++ )                               \
		    total += ((type *)op->elements)[i];                      \
		avg = total / op->counter;                                   \
		                                                             \
		total = 0;                                                   \
		for( i=0; i<op->counter; i++ )                               \
		    total += ( ((type *)op->elements)[i] - avg) *            \
		             ( ((type *)op->elements)[i] - avg);             \
		op->result.att = total / op->counter;                        \

const void* op_var_get_value( op_var_t *op ){
	int i;
	double total, avg, result;
	if( op->counter == 0 )
		return NULL;

	op->result.i = 0;
	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		CALCUL_var( float, f );
		break;
	//integer
	case MMT_U8_DATA:
		CALCUL_var( uint8_t, i );
		break;
	case MMT_U16_DATA:
		CALCUL_var( uint16_t, i );
		break;
	case MMT_U32_DATA:
		CALCUL_var( uint32_t, i );
		break;
	case MMT_U64_DATA:
		CALCUL_var( uint64_t, i );
		break;
	default:
		return NULL;
	}
	return &op->result;
}
