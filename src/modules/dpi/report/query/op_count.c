/*
 * op_count.c
 *
 *  Created on: Mar 29, 2022
 *      Author: nhnghia
 */

#include "operator.h"

typedef struct _op_count{
	uint64_t counter;
}op_count_t;

//this operator can handle any kind of data type
bool op_count_can_handle( data_types_t data_type ){
	return true;
}

data_types_t op_count_get_data_type( data_types_t data_type ){
	return MMT_U64_DATA;
}

void op_count_reset_value( op_count_t *op ){
	op->counter = 0;
}

op_count_t *op_count_create( data_types_t data_type ){
	op_count_t *op = mmt_alloc( sizeof( op_count_t) );
	op_count_reset_value( op );
	return op;
}

void op_count_release( op_count_t *op ){
	mmt_probe_free( op );
}

bool op_count_add_data( op_count_t *op, const void *value ){
	op->counter ++;
	return true;
}

const uint64_t * op_count_get_value( op_count_t *op ){
	return & op->counter;
}
