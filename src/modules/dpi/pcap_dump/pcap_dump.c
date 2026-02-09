/*
 * dump_data.c
 *
 *  Created on: Jan 12, 2018
 *          by: Huu Nghia
 */
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdlib.h>
#include <time.h>

#include "../dpi_tool.h"
#include "../../../lib/malloc_ext.h"
#include "../../../lib/memory.h"

typedef struct pcap_dump_context_struct{
	FILE *file;
	char file_name[MAX_LENGTH_FULL_PATH_FILE_NAME ];
	const pcap_dump_conf_t *config;
	size_t retain_count;
	uint32_t next_ts_to_dump_to_new_file;
	uint32_t *proto_ids_lst;
	uint16_t worker_index;
	uint32_t stack_type;
	size_t nb_dumped_packets;
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

void _close_pcap_file( pcap_dump_context_t *context ) {
	char new_file_name[MAX_LENGTH_FULL_PATH_FILE_NAME ];
	int err;
	size_t len;
	if( context->file == NULL)
		return;

	fclose( context->file );
	//rename to .pcap to make it available to other processes
	len = strlen( context->file_name );
	//context->file_name must be ._tmp
	if( len < 5 )
		return;

	if( len > MAX_LENGTH_FULL_PATH_FILE_NAME )
		len = MAX_LENGTH_FULL_PATH_FILE_NAME;
	memcpy( new_file_name, context->file_name, len );
	//manually change .tmp to .pcap
	new_file_name[len] = '\0';
	new_file_name[len-1] = 'p';
	new_file_name[len-2] = 'a';
	new_file_name[len-3] = 'c';
	new_file_name[len-4] = 'p';
	err = rename( context->file_name, new_file_name );
	if( err != 0 )
		log_write( LOG_ERR, "Cannot rename to %s: %s", new_file_name, strerror( errno ) );
	else
		log_write( LOG_INFO, "dumped %zu packets to %s", context->nb_dumped_packets, new_file_name );
}

// =======================> end of pcap file <=================================

static int _load_filter( const struct dirent *entry ){
	char *ext = strstr( entry->d_name, ".pcap" );
	if( ext == NULL ) return 0;
	return (strlen( ext ) == (sizeof( ".pcap" ) - 1) );
}
//* Remove old sampled files in #folder
static inline int _remove_old_sampled_files(const char *folder, size_t retains){
	struct dirent **entries, *entry;
	char file_name[ MAX_LENGTH_FULL_PATH_FILE_NAME ];
	int i, n, ret, to_remove, len, offset;

	n = scandir( folder, &entries, _load_filter, alphasort );
	if( n < 0 ) {
		log_write( LOG_ERR, "Cannot scan output_dir (%s): %s", folder, strerror( errno ) );
		return 0;
	}

	to_remove = n - retains - 1;
	//printf("total file %d, retains: %zu, to remove %d\n", n, retains, to_remove );
	if( to_remove < 0 )
		to_remove = 0;

	//preserve folder in file_name
	offset = strlen( folder );
	memcpy( file_name, folder, offset );

	//ensure folder is end by /
	if( file_name[ offset - 1 ] != '/' )
		file_name[ offset ++ ] = '/';

	//list of semaphore file
	for( i = 0 ; i < to_remove ; ++i ) {
		entry = entries[i];

		len = strlen( entry->d_name );

		//not enough room to contain file name
		if( len + offset >= sizeof( file_name ) ){
			log_write( LOG_WARNING, "Filename is too big: %s%s", file_name, entry->d_name );
			continue;
		}

		//get full path file
		memcpy(file_name + offset, entry->d_name, len + 1 ); //+1 to copy also '\0' character

		//delete file
		ret = unlink( file_name );
		if( ret )
			log_write( LOG_ERR, "Cannot delete file '%s': %s", file_name, strerror( errno ));
		else
			log_write( LOG_INFO, "Deleted old file '%s'", file_name );
	}

	for( i = 0; i < n; i++ )
		free( entries[ i ] );
	free( entries );

	return to_remove;
}

/**
 * This function must be called on each comming packet
 */
int pcap_dump_callback_on_receiving_packet(const ipacket_t * ipacket, pcap_dump_context_t *context) {

	//uint64_t last_proto = ipacket->proto_hierarchy->proto_path[ipacket->proto_hierarchy->len-1];
	int i, j;
	bool ret;

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
					_close_pcap_file( context );

				//reset counter
				context->nb_dumped_packets = 0;
				//set new file name
				(void)snprintf(context->file_name, MAX_LENGTH_FULL_PATH_FILE_NAME, "%s%lu_thread_%d.tmp_",
						context->config->directory,
						ipacket->p_hdr->ts.tv_sec,
						context->worker_index);

				//open new file
				context->file = _create_pcap_file( context->file_name, context->stack_type, 0, context->config->snap_len );
				if( context->file == NULL){
					log_write( LOG_ERR, "Cannot open file %s for dumping pcap: %s",
							context->file_name,
							strerror( errno )
					);
					return 0;
				} else
					//if we created successfully new file
					// => we will check if number of created files is bigger than the given number
					//    then we remove the oldest files to maintain this number
					if ( context->worker_index == 0 && context->retain_count > 0 ){
						_remove_old_sampled_files( context->config->directory,  context->retain_count );
					}

				context->next_ts_to_dump_to_new_file = ipacket->p_hdr->ts.tv_sec + context->config->frequency;
			}

			ret = _write_packet( context->file, (char*)ipacket->data,
					ipacket->p_hdr->len,
					//real length of packet to write to file
					MIN( ipacket->p_hdr->caplen, context->config->snap_len ),
					&(ipacket->p_hdr->ts));
			if( ret )
				context->nb_dumped_packets ++;
			return 0;
		}
	}
	return 0;
}


pcap_dump_context_t* pcap_dump_start( uint16_t worker_index, const probe_conf_t *probe_config, mmt_handler_t *dpi_handler ){
	pcap_dump_conf_t *config = probe_config->reports.pcap_dump;
	if( ! config->is_enable )
		return NULL;
	char msg[MAX_LENGTH_REPORT_MESSAGE];
	size_t index=0;

	pcap_dump_context_t *context = mmt_alloc_and_init_zero(sizeof( pcap_dump_context_t ));
	context->file = NULL;
	context->config = config;
	context->worker_index = worker_index;
	context->stack_type = probe_config->stack_type;
	context->retain_count = config->retained_files_count;
	if(context->retain_count > 0 && context->retain_count < probe_config->thread->thread_count ){
		context->retain_count = probe_config->thread->thread_count ;
		log_write( LOG_INFO, "Increased number of pcap files to keep to %zu (instead of %d) to equal to number of threads",
				context->retain_count,
				config->retained_files_count);
	}

	//protocol ids
	context->proto_ids_lst = mmt_alloc( sizeof( uint32_t ) * context->config->protocols_size );
	int i;
	for( i=0; i<context->config->protocols_size; i++ ){
		context->proto_ids_lst[i] = get_protocol_id_by_name( context->config->protocols[i] );
		index += snprintf(msg, MAX_LENGTH_REPORT_MESSAGE - index, ",%s", context->config->protocols[i] );
	}

	log_write(LOG_INFO, "Dump any packets containing protocol in the following list to '%s': %s",
			config->directory,
			&msg[1] //ignore the first comma ,
	);
	return context;
}

void pcap_dump_stop( pcap_dump_context_t *context ){
	if( context == NULL )
		return;
	_close_pcap_file( context );
	context->file = NULL;
	mmt_probe_free( context->proto_ids_lst );
	mmt_probe_free( context );
}
