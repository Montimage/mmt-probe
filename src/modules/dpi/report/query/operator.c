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
DECLARE_OP_HEADER( first )
DECLARE_OP_HEADER( last )

//a specific processing for array of operators
bool op_array_can_handle( query_op_type_t op, data_types_t data_type );
data_types_t op_array_get_data_type( query_op_type_t op, data_types_t data_type );
void op_array_reset_value( void* );
void* op_array_create( query_op_type_t op_type, data_types_t data_type );
void op_array_release( void* );
bool op_array_add_data( void*, const void *);
const void* op_array_get_value( void* );

static inline bool _is_array_processing( query_op_type_t op, data_types_t data_type ){
	//do not need an array of operators for "first" and "last" operators
	switch( op ){
	case QUERY_OP_FIRST:
	case QUERY_OP_LAST:
		return false;
	default:
		break;
	}

	switch( data_type ){
	case MMT_U16_ARRAY:
	case MMT_U32_ARRAY:
	case MMT_U64_ARRAY:
		return true;
	default:
		return false;
	}
}

const char* query_operator_get_name( query_op_type_t op ){
	switch( op ){
	case QUERY_OP_SUM:
		return "sum";
	case QUERY_OP_COUNT:
		return "count";
	case QUERY_OP_AVG:
		return "avg";
	case QUERY_OP_VAR:
		return "var";
	case QUERY_OP_DIFF:
		return "diff";
	case QUERY_OP_LAST:
		return "last";
	case QUERY_OP_FIRST:
		return "first";
	default:
		return false;
	}
}

bool query_operator_can_handle( query_op_type_t op, data_types_t data_type ){
	//specific for array data type
	if( _is_array_processing( op, data_type ) )
		return op_array_can_handle( op, data_type );

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
	case QUERY_OP_LAST:
		return op_last_can_handle(data_type);
	case QUERY_OP_FIRST:
		return op_first_can_handle(data_type);
	default:
		return false;
	}
}

data_types_t query_operator_get_data_type( query_op_type_t op, data_types_t data_type ){
	//specific for array data type
	if( _is_array_processing( op, data_type ) )
		return op_array_get_data_type( op, data_type );

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
	case QUERY_OP_LAST:
		return op_last_get_data_type(data_type);
	case QUERY_OP_FIRST:
		return op_first_get_data_type(data_type);
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
	query_operator_t *result;
	if( ! query_operator_can_handle(op, data_type ) )
		return NULL;
	result = mmt_alloc( sizeof( query_operator_t ));
	result->operator_type = op;
	result->data_type = data_type;

	if( _is_array_processing( op, data_type ) ){
		result->operator       = op_array_create(op, data_type);
		result->fn_release     = op_array_release;
		result->fn_get_value   = op_array_get_value;
		result->fn_reset_value = op_array_reset_value;
		result->fn_add_data    = op_array_add_data;
	} else {
		switch( op ){
		case QUERY_OP_SUM:
			ASSIGN_OP( result, sum );
			break;
		case QUERY_OP_COUNT:
			ASSIGN_OP( result, count );
			break;
		case QUERY_OP_AVG:
			ASSIGN_OP( result, avg );
			break;
		case QUERY_OP_VAR:
			ASSIGN_OP( result, var );
			break;
		case QUERY_OP_DIFF:
			ASSIGN_OP( result, diff );
			break;
		case QUERY_OP_LAST:
			ASSIGN_OP( result, last );
			break;
		case QUERY_OP_FIRST:
			ASSIGN_OP( result, first );
			break;
		default:
			mmt_probe_free( result );
			return NULL;
		}
		result->operator = result->fn_create( data_type );
	}
	return result;
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
