/*
 * operator_stack.c
 *
 *  Created on: Apr 5, 2022
 *      Author: nhnghia
 */

#include "operator_stack.h"

struct _query_operator_stack{
	size_t size;
	query_operator_t **operators;
	data_types_t result_data_type;
};

data_types_t query_operator_stack_get_data_type( const query_operator_stack_t* st){
	return st->result_data_type;
}

query_operator_stack_t *query_operator_stack_create( size_t operator_nb, const query_op_type_t* op_type, data_types_t data_type ){
	int i;
	if( operator_nb == 0 )
		return NULL;
	//TODO: need to check the compatibility of the operators in the stack:
	// whether the result of on operator can be taken as input of the next operator???
	query_operator_stack_t *st = mmt_alloc_and_init_zero( sizeof(query_operator_stack_t));
	st->size = operator_nb;
	st->operators = mmt_alloc( st->size * sizeof( void* ));
	//back track
	for( i = st->size - 1; i >= 0; i-- ){
		st->operators[i] = query_operator_create(op_type[i], data_type);
		//this operator cannot handle data_type
		//==> free memory
		if( st->operators[i] == NULL ){
			st->size = i;
			query_operator_stack_release( st );
			return NULL;
		}
		data_type = query_operator_get_data_type(op_type[i], data_type);
	}
	//returned data type of the last operator is also the one of this stack
	st->result_data_type = data_type;
	return st;
}

bool query_operator_stack_add_data( query_operator_stack_t *st, const void *data ){
	int i;
	bool b;
	//back track
	for( i = st->size - 1; i >= 0; i-- ){
		b = query_operator_add_data( st->operators[i], data );
		if( b == false )
			return false;
		//we do not need to get value of the last operator
		// since it will not be used
		if( i>0 )
			data = query_operator_get_value( st->operators[i] );
	}
	return true;
}

const void *query_operator_stack_get_value( const query_operator_stack_t *st ){
	//that is the result of the operator on the top of the stack
	return query_operator_get_value( st->operators[0] );
}

void query_operator_stack_reset_value( query_operator_stack_t *st ){
	int i;
	for( i=0; i<st->size; i++ )
		query_operator_reset_value( st->operators[i] );
}

void query_operator_stack_release( query_operator_stack_t *st ){
	int i;
	if( st == NULL )
		return;
	//release each operator
	for( i=0; i<st->size; i++ )
		query_operator_release( st->operators[i] );
	mmt_probe_free( st->operators );
	mmt_probe_free( st );
}
