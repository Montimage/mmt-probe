/*
 * operator_stack.h
 *
 *  Stack of operators
 *
 *  Created on: Apr 5, 2022
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_REPORT_QUERY_OPERATOR_STACK_H_
#define SRC_MODULES_DPI_REPORT_QUERY_OPERATOR_STACK_H_

#include "operator.h"

typedef struct _query_operator_stack query_operator_stack_t;

data_types_t query_operator_stack_get_data_type( const query_operator_stack_t* );

query_operator_stack_t *query_operator_stack_create( size_t operator_nb, const query_op_type_t* t, data_types_t data_type );

bool query_operator_stack_add_data( query_operator_stack_t *q, const void *data );

const void *query_operator_stack_get_value( const query_operator_stack_t *st );

void query_operator_stack_reset_value( query_operator_stack_t *q );

void query_operator_stack_release( query_operator_stack_t *q );

#endif /* SRC_MODULES_DPI_REPORT_QUERY_OPERATOR_STACK_H_ */
