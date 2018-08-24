/*
 * dump_data.c
 *
 *  Created on: Jan 12, 2018
 *          by: Huu Nghia
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

#include "../dpi_tool.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

typedef struct pcap_dump_context_struct{
	FILE *file;
	const pcap_dump_conf_t *config;
	uint32_t next_ts_to_dump_to_new_file;
	uint32_t *proto_ids_lst;
	uint16_t worker_index;
} pcap_dump_context_t;


// =======================> pcap file <=================================
struct pd_timeval {
	uint32_t tv_sec;     /* seconds */
	uint32_t tv_usec;    /* microseconds */
};

//see: https://wiki.wireshark.org/Development/LibpcapFileFormat
struct pd_pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;     /* accuracy of timestamps */
	uint32_t snaplen;     /* max length saved portion of each pkt */
	uint32_t linktype;    /* data link type (LINKTYPE_*) */
};

struct pd_pcap_pkthdr {
	struct pd_timeval ts;  /* time stamp using 32 bits fields */
	uint32_t caplen;       /* length of portion present */
	uint32_t len;          /* length this packet (off wire) */
};



static inline bool _write_packet( FILE *fd, const char * buf, uint16_t len, uint16_t caplen, const struct timeval *tv) {
    struct pd_pcap_pkthdr h;

    h.ts.tv_sec  = (uint32_t)tv->tv_sec;
    h.ts.tv_usec = (uint32_t)tv->tv_usec;

    h.caplen = caplen;
    h.len = len;

    //write header
    if( fwrite( &h, sizeof( h ), 1, fd ) != 1 )
    	return false;

    //write packet data
    if( fwrite( buf, sizeof( char ), caplen, fd ) != caplen)
    	return false;

    return true;
}

FILE * _create_pcap_file(const char * path, int linktype, int thiszone, uint16_t snaplen) {
	//open file for writing
    FILE *file = fopen( path, "w" );
    if (file == NULL)
    	return NULL;

    //write header of pcap file
    struct pd_pcap_file_header hdr;
    hdr.magic = 0xa1b2c3d4; //
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    fwrite( &hdr, sizeof( hdr ), 1, file );

    return file;
}

void _close_pcap_file( FILE *file ) {
	if( file )
		fclose( file );
}

// =======================> end of pcap file <=================================


/**
 * This function must be called on each comming packet
 */
int pcap_dump_callback_on_receiving_packet(const ipacket_t * ipacket, pcap_dump_context_t *context) {
	char file_name[MAX_LENGTH_FULL_PATH_FILE_NAME ];

	//uint64_t last_proto = ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len-1];
	int i, j;

	//for each protocol need to be dump
	//=> need to check if it exists inside protocol hierarchy of packet
	for( i = 0; i < context->config->protocols_size; i++ ){
		int proto_to_check = context->proto_ids_lst[i];

		for(j = ipacket->proto_hierarchy->len - 1; j > 1; j--){
			if(ipacket->proto_hierarchy->proto_path[j] != proto_to_check)
				continue;

			//found one protocol
			//check periodically
			if( context->file == NULL
					|| ipacket->p_hdr->ts.tv_sec  > context->next_ts_to_dump_to_new_file ){

				//close old file
				if( context->file != NULL )
					_close_pcap_file( context->file );

				//set new file name
				(void)snprintf(file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s%lu_thread_%d.pcap",
						context->config->directory,
						ipacket->p_hdr->ts.tv_sec,
						context->worker_index);

				//open new file
				context->file = _create_pcap_file( file_name, DLT_EN10MB, 0, context->config->snap_len );
				if( context->file == NULL){
					log_write( LOG_ERR, "Cannot open file %s for dumping pcap: %s",
							file_name,
							strerror( errno )
					);
					return 0;
				}
				context->next_ts_to_dump_to_new_file = ipacket->p_hdr->ts.tv_sec + context->config->frequency;
			}

			_write_packet( context->file, (char*)ipacket->data,
					ipacket->p_hdr->len,
					//real length of packet to write to file
					MIN( ipacket->p_hdr->caplen, context->config->snap_len ),
					&(ipacket->p_hdr->ts));

			return 0;
		}
	}
	return 0;
}


pcap_dump_context_t* pcap_dump_start( uint16_t worker_index, pcap_dump_conf_t *config, mmt_handler_t *dpi_handler ){
	if( ! config->is_enable )
		return NULL;

	pcap_dump_context_t *context = mmt_alloc_and_init_zero(sizeof( pcap_dump_context_t ));
	context->file = NULL;
	context->config = config;
	context->worker_index = worker_index;

	//protocol ids
	context->proto_ids_lst = mmt_alloc( sizeof( uint32_t ) * context->config->protocols_size );
	int i;
	for( i=0; i<context->config->protocols_size; i++ )
		context->proto_ids_lst[i] = get_protocol_id_by_name( context->config->protocols[i] );

	return context;
}

void pcap_dump_stop( pcap_dump_context_t *context ){
	if( context == NULL )
		return;
	_close_pcap_file( context->file );
	context->file = NULL;
	mmt_probe_free( context->proto_ids_lst );
	mmt_probe_free( context );
}
