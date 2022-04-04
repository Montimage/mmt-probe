/*
 * operator.c
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */

#include "operator.h"

#define DECLARE_OP_HEADER( OP )                               \
	int         op_## OP ##_get_data_type(int);               \
	bool        op_## OP ##_can_handle(int);                  \
	void*       op_## OP ##_create(int);                      \
	void        op_## OP ##_release(void*);                   \
	bool        op_## OP ##_add_data(void*, const void*);     \
	const void* op_## OP ##_get_value(void*);                 \
	void        op_## OP ##_reset_value(void *);

struct _query_operator{
	query_op_type_t operator_type;
	data_types_t data_type;
	void *operator; //to store either
	void *       (*fn_create)(int);
	bool         (*fn_add_data)(void *, const void*);
	const void * (*fn_get_value)(void*);
	void         (*fn_reset_value)(void*);
	void         (*fn_release)(void*);
};

DECLARE_OP_HEADER( sum )
DECLARE_OP_HEADER( count )
DECLARE_OP_HEADER( avg )
DECLARE_OP_HEADER( var )
DECLARE_OP_HEADER( diff )

bool query_operator_can_handle( query_op_type_t op, data_types_t data_type ){
	switch( op ){
	case QUERY_OP_SUM:
		return op_sum_can_handle(data_type);
	case QUERY_OP_COUNT:
		return op_count_can_handle(data_type);
	case QUERY_OP_AVG:
		return op_avg_can_handle(data_type);
	case QUERY_OP_VAR:
		return op_var_can_handle(data_type);
	case QUERY_OP_DIFF:
		return op_diff_can_handle(data_type);
	default:
		return false;
	}
}

data_types_t query_operator_get_data_type( query_op_type_t op, data_types_t data_type ){
	switch( op ){
	case QUERY_OP_SUM:
		return op_sum_get_data_type(data_type);
	case QUERY_OP_COUNT:
		return op_count_get_data_type(data_type);
	case QUERY_OP_AVG:
		return op_avg_get_data_type(data_type);
	case QUERY_OP_VAR:
		return op_var_get_data_type(data_type);
	case QUERY_OP_DIFF:
		return op_diff_get_data_type(data_type);
	default:
		return false;
	}
}

#define ASSIGN_OP(result, op)                             \
	result->fn_create      = op_## op ##_create;          \
	result->fn_release     = op_## op ##_release;         \
	result->fn_add_data    = op_## op ##_add_data;        \
	result->fn_reset_value = op_## op ##_reset_value;     \
	result->fn_get_value   = op_## op ##_get_value;       \

query_operator_t *query_operator_create( query_op_type_t op, data_types_t data_type ){
	query_operator_t *result = mmt_alloc( sizeof( query_operator_t ));
	result->operator_type = op;
	result->data_type = data_type;

	switch( op ){
	case QUERY_OP_SUM:
		if( ! op_sum_can_handle(data_type) )
			goto _query_operator_create_fail;
		ASSIGN_OP( result, sum );
		break;
	case QUERY_OP_COUNT:
		if( ! op_count_can_handle(data_type) )
			goto _query_operator_create_fail;
		ASSIGN_OP( result, count );
		break;
	case QUERY_OP_AVG:
		if( ! op_avg_can_handle(data_type) )
			goto _query_operator_create_fail;
		ASSIGN_OP( result, avg );
		break;
	case QUERY_OP_VAR:
		if( ! op_var_can_handle(data_type) )
			goto _query_operator_create_fail;
		ASSIGN_OP( result, var );
		break;
	case QUERY_OP_DIFF:
		if( ! op_diff_can_handle(data_type) )
			goto _query_operator_create_fail;
		ASSIGN_OP( result, diff );
		break;
	default:
		goto _query_operator_create_fail;
	}
	result->operator = result->fn_create( data_type );
	return result;

	_query_operator_create_fail:
	mmt_probe_free( result );
	return NULL;
}


query_operator_t *query_operator_duplicate( const query_operator_t* op ){
	return query_operator_create( op->operator_type, op->data_type );
}

bool query_operator_add_data( query_operator_t *q, const void *data ){
	return q->fn_add_data(q->operator, data);
}

const void *query_operator_get_value( query_operator_t *q ){
	return q->fn_get_value(q->operator);
}

void query_operator_reset_value( query_operator_t *q ){
	return q->fn_reset_value(q->operator);
}

void query_operator_release( query_operator_t *q ){
	if( q == NULL )
		return;
	q->fn_release(q->operator);
	mmt_probe_free( q );
}
