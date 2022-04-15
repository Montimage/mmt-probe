/*
 * operation.h
 *
 *  Created on: Mar 30, 2022
 *      Author: nhnghia
 */

#ifndef SRC_MODULES_DPI_REPORT_QUERY_OPERATOR_H_
#define SRC_MODULES_DPI_REPORT_QUERY_OPERATOR_H_

#include "../../../../lib/memory.h"
#include "../../../../lib/malloc.h"
#include <mmt_core.h>

typedef enum {
	QUERY_OP_SUM = 1, //total
	QUERY_OP_COUNT,
	QUERY_OP_AVG,     //average value
	QUERY_OP_VAR,     //variance
	QUERY_OP_DIFF,    //difference with the previous value
	QUERY_OP_LAST,    //the latest value
	QUERY_OP_FIRST,   //the first value
}query_op_type_t;

typedef enum data_types data_types_t;

typedef struct _query_operator query_operator_t;

const char* query_operator_get_name( query_op_type_t op );

bool query_operator_can_handle( query_op_type_t op, data_types_t data_type );

data_types_t query_operator_get_data_type( query_op_type_t op, data_types_t data_type  );

query_operator_t *query_operator_create( query_op_type_t t, data_types_t data_type );

query_operator_t *query_operator_duplicate( const query_operator_t* );

bool query_operator_add_data( query_operator_t *q, const void *data );

const void *query_operator_get_value( query_operator_t *q );

void query_operator_reset_value( query_operator_t *q );

void query_operator_release( query_operator_t *q );



#endif /* SRC_MODULES_DPI_REPORT_QUERY_OPERATION_H_ */
