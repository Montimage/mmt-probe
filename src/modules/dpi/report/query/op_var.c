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
	uint32_t elements_size;
	void *elements;
	float result;
}op_var_t;

data_types_t op_var_get_data_type( data_types_t data_type ){
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

bool op_var_can_handle( data_types_t data_type ){
	return op_var_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_var_reset_value( op_var_t *op ){
	op->counter = 0;
	op->result  = 0;
}

op_var_t *op_var_create( data_types_t data_type ){
	op_var_t *op = mmt_alloc( sizeof( op_var_t ));
	op->data_type = data_type;
	op->elements_size = ELEMENTS_SIZE;

	switch( data_type ){
	case MMT_DATA_FLOAT:
		op->elements = mmt_alloc( op->elements_size * sizeof(float) );
		break;
	case MMT_U8_DATA:
		op->elements = mmt_alloc( op->elements_size * sizeof( uint8_t) );
		break;
	case MMT_U16_DATA:
		op->elements = mmt_alloc( op->elements_size * sizeof( uint16_t ) );
		break;
	case MMT_U32_DATA:
		op->elements = mmt_alloc( op->elements_size * sizeof( uint32_t ) );
		break;
	case MMT_U64_DATA:
		op->elements = mmt_alloc( op->elements_size * sizeof( uint64_t ) );
		break;
	default:
		//this avoid adding data
		op->elements_size = 0;
		op->elements = NULL;
		break;
	}

	op_var_reset_value( op );
	return op;
}

void op_var_release( op_var_t *op ){
	if( op )
		mmt_probe_free( op->elements );
	mmt_probe_free( op );
}

bool op_var_add_data( op_var_t *op, const void* value ){
	//table is full
	if( op->counter >= op->elements_size )
		return false;

	switch( op->data_type ){
	//float
	case MMT_DATA_FLOAT:
		((float*) op->elements)[ op->counter ] = *(float *) value;
		op->counter ++;
		return true;
	//integer
	case MMT_U8_DATA:
		((uint8_t*) op->elements)[ op->counter ] = *(uint8_t *) value;
		op->counter ++;
		return true;
	case MMT_U16_DATA:
		((uint16_t*) op->elements)[ op->counter ] = *(uint16_t *) value;
		op->counter ++;
		return true;
	case MMT_U32_DATA:
		((uint32_t*) op->elements)[ op->counter ] = *(uint32_t *) value;
		op->counter ++;
		return true;
	case MMT_U64_DATA:
		((uint64_t*) op->elements)[ op->counter ] = *(uint64_t *) value;
		op->counter ++;
		return true;
	default:
		return false;
	}

	return true;
}

//calculate a var is performed in 2 steps:
// 1. calculate average of elements
// 2.
#define CALCUL_var( type )                                      \
		total = 0;                                                   \
		for( i=0; i<op->counter; i++ )                               \
			total += ((type *)op->elements)[i];                      \
		avg = total / op->counter;                                   \
		                                                             \
		total = 0;                                                   \
		for( i=0; i<op->counter; i++ )                               \
			total += ( ((type *)op->elements)[i] - avg) *            \
			         ( ((type *)op->elements)[i] - avg);             \
		op->result = total / op->counter;                            \

const void* op_var_get_value( op_var_t *op ){
	int i;
	float total, avg;
	if( op->counter == 0 )
		op->result = 0;
	else {
		float total = 0;
		switch( op->data_type ){
		//float
		case MMT_DATA_FLOAT:
			CALCUL_var( float );
			break;
		//integer
		case MMT_U8_DATA:
			CALCUL_var( uint8_t );
			break;
		case MMT_U16_DATA:
			CALCUL_var( uint16_t );
			break;
		case MMT_U32_DATA:
			CALCUL_var( uint32_t );
			break;
		case MMT_U64_DATA:
			CALCUL_var( uint64_t );
			break;
		default:
			op->result = 0;
		}
	}
	return &op->result;
}
