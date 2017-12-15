/*
 * packet_processing.c
 *
 *  Created on: Dec 14, 2017
 *      Author: nhnghia
 */

#include "processing.h"

void packet_processing( single_thread_context_t *worker_context, struct pkthdr *header, const u_char *pkt_data ){
	worker_context->stat.pkt_processed ++;
	printf("%d %5d %5d\n", worker_context->index, header->caplen, header->len );
	//fflush( stdout );
}
