/*
 * op_diff.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */



#include "operator.h"

typedef struct _op{
	data_types_t data_type;
	bool hash_first_value;
	void *result;
	uint32_t data_size;
}op_first_t;

data_types_t op_first_get_data_type( data_types_t data_type ){
	//the result should be the same
	return data_type;
}

bool op_first_can_handle( data_types_t data_type ){
	return op_first_get_data_type( data_type ) != MMT_UNDEFINED_TYPE;
}

void op_first_reset_value( op_first_t *op ){
	op->hash_first_value = false;
}

op_first_t *op_first_create( data_types_t data_type ){
	op_first_t *op = mmt_alloc( sizeof( op_first_t ));
	op->data_size = get_data_size_by_data_type( data_type );
	op->data_type = data_type;
	op->result = mmt_alloc( op->data_size );
	op_first_reset_value( op );
	return op;
}

void op_first_release( op_first_t *op ){
	if( op == NULL )
			return;
	mmt_probe_free( op->result );
	mmt_probe_free( op );
}

bool op_first_add_data( op_first_t *op, const void* value ){
	//store the value only if it was not done
	if( !op->hash_first_value )
		memcpy(op->result, value, op->data_size);
	op->hash_first_value = true;
	return true;
}

const void* op_first_get_value( op_first_t *op ){
	if( ! op->hash_first_value )
		return NULL;
	return op->result;
}
