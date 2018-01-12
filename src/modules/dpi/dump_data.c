/*
 * dump_data.c
 *
 *  Created on: Jan 12, 2018
 *          by: Huu Nghia
 */

#include "../../lib/pcap_dump.h"
#include "dpi_tool.h"
#include "dpi.h"

typedef struct data_dump_context_struct{
	int dump_file_handler;
	const data_dump_conf_t *config;
	struct timeval last_dump_ts;
	long u_frequency;
	int worker_index;
} data_dump_context_t;

static int _packet_handler_to_dump_data(const ipacket_t * ipacket, void * args) {
	data_dump_context_t *context = (data_dump_context_t *)args;
	char file_name[MAX_LENGTH_FULL_PATH_FILE_NAME ];
	uint64_t last_proto = ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len-1];
	int i, j;
	//for each protocol need to be dump
	for( i = 0; i < context->config->protocols_size; i++ ){
		int proto_to_check;// = context->protocols_id[z];

		for(j = ipacket->proto_hierarchy->len - 1; j > 1; j--){
			if(ipacket->proto_hierarchy->proto_path[j] != proto_to_check)
				continue;
			//found one protocol

			//check periodically
			if( context->dump_file_handler <= 0 || u_second_diff( &ipacket->p_hdr->ts, &context->last_dump_ts) >= context->u_frequency ){
				//close old file
				if( context->dump_file_handler > 0 )
					pd_close( context->dump_file_handler );

				//set new file name
				(void)snprintf(file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s%lu_thread_%d.pcap",
						context->config->directory,
						ipacket->p_hdr->ts.tv_sec,
						context->worker_index);

				//open new file
				context->dump_file_handler = pd_open( file_name );
				if( context->dump_file_handler == -1){
					log_write( LOG_ERR, "Cannot open file %s for dumping pcap: %s",
							file_name,
							strerror( errno )
					);
					return 0;
				}
				context->last_dump_ts = ipacket->p_hdr->ts;
			}

			pd_write( context->dump_file_handler, (char*)ipacket->data,
					ipacket->p_hdr->caplen, &ipacket->p_hdr->ts);

			return 0;
		}
	}
	return 0;
}


void data_dump_start( dpi_context_t *dpi_context ){
	if( ! dpi_context->probe_config->reports.data_dump->is_enable )
		return;

	data_dump_context_t *context = alloc( sizeof( data_dump_context_t ));
	context->dump_file_handler = 0;
	context->config = dpi_context->probe_config->reports.data_dump;
	context->worker_index = dpi_context->worker_index;
	context->u_frequency = context->config->frequency * 1000000;
	dpi_context->data_dump_context = context;


	mmt_handler_t *dpi_handler = dpi_context->dpi_handler;
	//register protocols
	int i;
//	for( i=0; i<context->config->protocols_size; i++ ){
//		const char* proto_name = context->config->protocols[i];
//
//	}
	int ret = register_packet_handler( dpi_handler, 7, _packet_handler_to_dump_data, context );
	if( ! ret)
		ABORT( "Cannot register packet handler for data dumping" );
}
void data_dump_stop( dpi_context_t *dpi_context ){

}
