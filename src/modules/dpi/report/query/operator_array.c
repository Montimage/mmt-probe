/*
 * operator_array.c
 *
 * A specific adapter for array data types, such as, MMT_U32_ARRAY, MMT_U64_ARRAY
 * It is done by using the operator on each element of the array
 * Currently we support only the operators that return the same data type as the one of each element.
 * For example, the operators must return MMT_U32_DATA when processing MMT_U32_ARRAY.
 *
 *  Created on: Apr 11, 2022
 *      Author: nhnghia
 */


#include "operator.h"


#define ARRAY_SIZE BINARY_64DATA_LEN
typedef struct op_array_ {
	data_types_t data_type;
	query_op_type_t op_type;
	data_types_t el_op_data_type; //data type of element operator
	size_t size;
	void *operators[ ARRAY_SIZE ];
	union {
		mmt_u32_array_t u32;
		mmt_u64_array_t u64;
	} result;
} op_array_t;

static inline data_types_t _get_element_data_type( data_types_t data_type ){
	switch( data_type ){
	case MMT_U16_ARRAY:
		return MMT_U16_DATA;
	case MMT_U32_ARRAY:
		return MMT_U32_DATA;
	case MMT_U64_ARRAY:
		return MMT_U64_DATA;
	default:
		return MMT_UNDEFINED_TYPE;
	}
}

bool op_array_can_handle( query_op_type_t op, data_types_t data_type ){
	data_types_t el_data_type = _get_element_data_type(data_type);
	data_types_t ret_el_data_type = query_operator_get_data_type( op, el_data_type );
	//we can support only the operators that return a numeric value
	switch( ret_el_data_type ){
	case MMT_U8_DATA:
	case MMT_U16_DATA:
	case MMT_U32_DATA:
	case MMT_U64_DATA:
	case MMT_DATA_FLOAT:
		return true;
	default:
		return false;
	}
	return
		//must be handled by the operator
		query_operator_can_handle( op, el_data_type );
}


data_types_t op_array_get_data_type( query_op_type_t op, data_types_t data_type ){
	switch( data_type ){
	case MMT_U32_ARRAY:
	case MMT_U64_ARRAY:
		if( op_array_can_handle( op, data_type))
			return data_type;
		else
			break;
	default:
		break;
	}
	return MMT_UNDEFINED_TYPE;
}

void op_array_reset_value( op_array_t *op ){
	size_t i;
	for( i=0; i<op->size; i++ )
		query_operator_reset_value( op->operators[i] );
	memset( &op->result, 0, sizeof( op->result));
}

op_array_t* op_array_create( query_op_type_t op_type, data_types_t data_type ){
	op_array_t *op;
	if( !op_array_can_handle( op_type, data_type) )
		return NULL;

	op = mmt_alloc( sizeof( op_array_t ) );
	op->size = 0;
	op->data_type = data_type;
	op->op_type   = op_type;
	op->el_op_data_type = query_operator_get_data_type(op_type, _get_element_data_type( data_type));
	op_array_reset_value( op );
	return op;
}

void op_array_release( op_array_t *op){
	size_t i;
	for( i=0; i<op->size; i++ ){
		query_operator_release( op->operators[i] );
	}
	mmt_probe_free( op );
}

static inline void _init_operators( op_array_t *op, size_t nb_operators ){
	size_t i;
	data_types_t el_data_type = _get_element_data_type( op->data_type );
	//should not occur this, but checking anyway
	if( nb_operators > ARRAY_SIZE )
		nb_operators = ARRAY_SIZE;
	op->size = nb_operators;
	for( i=0; i<op->size; i++ )
		op->operators[i] = query_operator_create(op->op_type, el_data_type );
}

#define _SET_DATA( u )\
	if( u->len == 0 )                                                              \
	   return false;                                                               \
	if( op->size == 0 )                                                            \
	   _init_operators( op, u->len );                                              \
	if( u->len != op->size ){                                                      \
	   log_write(LOG_ERR, "Expected data length %zu, got %d", op->size, u->len );  \
	   return false;                                                               \
	}                                                                              \
	for( i=0; i<op->size; i++ )                                                    \
	   if( ! query_operator_add_data( op->operators[i], & u->data[i] ) )           \
	      ret = false;

bool op_array_add_data( op_array_t *op, const void *data){
	size_t i, len;
	bool ret = true;
	mmt_u32_array_t *u32 = (mmt_u32_array_t *) data;
	mmt_u64_array_t *u64 = (mmt_u64_array_t *) data;
	if( data == NULL )
		return false;
	switch( op->data_type ){
	case MMT_U32_ARRAY:
		_SET_DATA( u32 );
		break;
	case MMT_U64_ARRAY:
		_SET_DATA( u64 );
		break;
	default:
		return false;
	}
	return ret;
}
const void* op_array_get_value( op_array_t *op){
	size_t i;
	const void *p;
	uint64_t val;
	for( i=0; i<op->size; i++ ){
		p = query_operator_get_value( op->operators[i] );
		//use the default value
		if( p == NULL )
			continue;
		switch( op->el_op_data_type ){
		case MMT_U8_DATA:
			val = *(uint8_t *) p;
			break;
		case MMT_U16_DATA:
			val = *(uint16_t *) p;
			break;
		case MMT_U32_DATA:
			val = *(uint32_t *) p;
			break;
		case MMT_U64_DATA:
			val = *(uint64_t *) p;
			break;
		case MMT_DATA_FLOAT:
			val = *(float *) p;
			break;
		default:
			//reset to default value (zero)
			val = 0;
		}
		if( op->data_type == MMT_U64_ARRAY )
			op->result.u64.data[i] = val;
		else
			op->result.u32.data[i] = val;
	}

	//update number of elements
	if( op->data_type == MMT_U64_ARRAY )
		op->result.u64.len = op->size;
	else
		op->result.u32.len = op->size;

	return &op->result;
}
