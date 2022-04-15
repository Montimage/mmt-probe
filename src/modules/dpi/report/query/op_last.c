/*
 * op_diff.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op{
	data_types_t data_type;
	bool has_last_value;
	void *result;
	uint32_t data_size;
}op_last_t;

data_types_t op_last_get_data_type( data_types_t data_type ){
	//the result should be the same
	return data_type;
}

bool op_last_can_handle( data_types_t data_type ){
	return op_last_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_last_reset_value( op_last_t *op ){
	op->has_last_value = false;
}

op_last_t *op_last_create( data_types_t data_type ){
	op_last_t *op = mmt_alloc( sizeof( op_last_t ));
	op->data_size = get_data_size_by_data_type( data_type );
	op->data_type = data_type;
	op->result = mmt_alloc( op->data_size );
	op_last_reset_value( op );
	return op;
}

void op_last_release( op_last_t *op ){
	if( op == NULL )
		return;
	mmt_probe_free( op->result );
	mmt_probe_free( op );
}

bool op_last_add_data( op_last_t *op, const void* value ){
	memcpy(op->result, value, op->data_size);
	op->has_last_value = true;
	return true;
}

const void* op_last_get_value( op_last_t *op ){
	if( ! op->has_last_value )
		return NULL;
	return op->result;
}
