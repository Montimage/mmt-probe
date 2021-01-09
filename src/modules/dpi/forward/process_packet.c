/*
 * process_packet.c
 *
 *  Created on: Jan 8, 2021
 *      Author: nhnghia
 */

#include "process_packet.h"

uint64_t get_number_value(uint32_t proto_id, uint32_t att_id,
		const mmt_array_t *const trace) {
	const message_t *msg;
	const message_element_t *me;
	uint64_t value = 0;
	int i, j;
	for (i = 0; i < trace->elements_count; i++) {
		msg = trace->data[i];
		if( !msg )
			continue;
		for (j = 0; j < msg->elements_count; j++) {
			me = &msg->elements[i];
			if( !me )
				continue;
			if (me->proto_id == proto_id && me->att_id == att_id) {
				if (me->data_type == MMT_SEC_MSG_DATA_TYPE_NUMERIC)
					value = *(double*) me->data;
				return value;
			}
		}
	}
	return value;
}
