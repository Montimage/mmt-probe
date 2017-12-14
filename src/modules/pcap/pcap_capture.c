/*
 * pcap_capture.h
 *
 *  Created on: Dec 13, 2017
 *      Author: nhnghia
 */



#include <pthread.h>
#include <pcap.h>


#include "pcap_capture.h"
#include "../../lib/packet_processing.h"
#include "../../lib/alloc.h"

#define __HASH_TABLE_SIZE 100000

//for one thread
struct pcap_single_thread_context_struct{
	pthread_t thread_handler;
	pthread_spinlock_t spin_lock;
};

//for all application
struct pcap_context_struct{
	pcap_t *handler;
};

uint32_t _get_index( uint32_t nu ){
	static uint32_t hash_table[ __HASH_TABLE_SIZE ];
	static uint32_t length = 0;
	static uint32_t i, cache_index = 0;

	if( hash_table[ cache_index ] == nu ) return cache_index;

	//check if this number exists in the hash table
	for( i=0; i<length; i++ )
		if( hash_table[i] == nu ){
			cache_index = i;
			return i;
		}

	//if not, add it
	hash_table[ length ] = nu;
	cache_index = length;

	length ++;

	if( unlikely( length >= __HASH_TABLE_SIZE ))
		length = 0;

	return cache_index;
}


/**
 * Hash function of an Ethernet packet
 */
static inline uint32_t _get_packet_hash_number( const uint8_t *packet, size_t pkt_len ){
	//Ethernet structure
	struct __ethernet_struct {
		uint8_t src[6];
		uint8_t dst[6];
		uint16_t proto;
	} *eth;

	uint32_t a1, a2;
	uint16_t ip_src_off;

	if ( unlikely( pkt_len < 38))
		return 0; //TODO: this is not elegant check IP, IPv6 etc.

	eth = (struct __ethernet_struct *) packet;


	switch( eth->proto ){
	//IP
	case 0x08:
		ip_src_off = 26;
		break;
	//vlan
	case 0x81:
		ip_src_off = 30;
		break;
	default:
		//for other protocol
		return 0;
	}

	a1 = *((uint32_t *) &packet[ ip_src_off     ]);
	a2 = *((uint32_t *) &packet[ ip_src_off + 4 ]);
//
//	/*proto_id = *((uint8_t *) &packet[ ip_src_off - 3 ]);
//	//src and dst ports of TCP or UDP
//	if( likely(proto_id == 6 || proto_id == 17 )){
//		p1 = *((uint16_t *) &packet[ ip_src_off + 8]);
//		p2 = *((uint16_t *) &packet[ ip_src_off + 8 + 2]);
//	}
//	else
//		p1 = p2 = 0;*/
//
//	printf("%s src: %03d.%03d.%03d.%03d, dst: %03d.%03d.%03d.%03d \n",
//			proto_id == 6? "TCP" :( proto_id == 17? "UDP" : "---"),
//			(a1 >> 24), ((a1 << 8) >> 24), ((a1 << 16) >> 24), ((a1 << 24) >> 24),
//			(a2 >> 24), ((a2 << 8) >> 24), ((a2 << 16) >> 24), ((a2 << 24) >> 24)
//			);
//	//exit( 0 );
//
////	a1 = (a1 >> 24) + (a1 >> 16) + (a1 >> 8) + a1;
////	a2 = (a2 >> 24) + (a2 >> 16) + (a2 >> 8) + a2;
//
	return (a1 & a2) ^ (a1 | a2);
}

static void got_a_packet(u_char* user, const struct pcap_pkthdr *pcap_header, const u_char *pcap_data){
	probe_context_t *context =( probe_context_t *)user;
	struct pkthdr header;

	//convert from pcap's header to mmt packet's header
	header.ts        = pcap_header->ts;
	header.caplen    = pcap_header->caplen;
	header.len       = pcap_header->len;
	header.user_args = NULL;

	if( context->config->thread->thread_count == 1 )
		packet_processing(context, &header, pcap_data );
	else{
		//multithreading
		uint32_t pkt_index = _get_packet_hash_number(pcap_data, pcap_header->caplen ) % context->config->thread->thread_count;
		printf("%d\n", pkt_index);
	}
}

//PUBLIC API
void pcap_capture_close( probe_context_t *context ){
	struct pcap_stat pcs; //packet capture stats
	int i;
	u_int pkt_received;

	//stop processing packets
	pcap_breakloop( context->modules.pcap->handler );

	print_statistics( context );

	//get statistics from pcap
	if( context->config->input->input_mode == ONLINE_ANALYSIS ){
		if (pcap_stats(context->modules.pcap->handler, &pcs) < 0) {
			log_write( LOG_WARNING, "Cannot get statistics from pcap: %s\n", pcap_geterr( context->modules.pcap->handler ));
		}else{
			pkt_received = pcs.ps_recv;
			log_write( LOG_INFO, "\n%12d packets received by filter\n", pkt_received);
			log_write( LOG_INFO, "%12d packets dropped by NIC (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pkt_received);
			log_write( LOG_INFO, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0  / pkt_received);
		}
	}

	//close
	pcap_close( context->modules.pcap->handler );
}



//public API
void pcap_capture_start( probe_context_t *context ){
	int i, ret;
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	pcap_t *pcap;

	void( *proc )( probe_context_t*, struct pkthdr *, const u_char* );

	log_write( LOG_INFO, "Starting PCAP mode to analyze '%s' using %d thread(s)",
			context->config->input->input_source,
			context->config->thread->thread_count );

	context->modules.pcap = alloc( sizeof( struct pcap_context_struct ));

	//allocate context for each thread
	context->smp = alloc( sizeof( single_thread_context_t ) * context->config->thread->thread_count );

	for( i=0; i<context->config->thread->thread_count; i++ ){
		context->smp[i] = alloc_init_single_thread_context_t();

		context->smp[i]->index = i;

		//specific for pcap module
		context->smp[i]->pcap = alloc( sizeof( struct pcap_single_thread_context_struct ));
		//init
		pthread_spin_init( & context->smp[i]->pcap->spin_lock, PTHREAD_PROCESS_PRIVATE);
	}


	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		pcap = pcap_open_offline( context->config->input->input_source, errbuf );
	}else{
		/* open capture device */
		pcap = pcap_create(context->config->input->input_source, errbuf);
		if ( pcap == NULL ) {
			log_write( LOG_ERR, "Couldn't open device %s\n", errbuf);
			exit(0);
		}

		//set IP packet size
		ret = pcap_set_snaplen( pcap, context->config->input->snap_len );
		//put NIC to promiscuous mode to capture any packets
		ret = pcap_set_promisc( pcap, true );
		if( ret != 0 ){
			log_write( LOG_ERR, "Cannot put '%s' NIC to promiscuous mode", context->config->input->input_source);
			exit( EXIT_FAILURE );
		}
		ret = pcap_set_timeout( pcap, 0 );
		//buffer size
		pcap_set_buffer_size(pcap, 500*1000*1000);
		pcap_activate(pcap);
	}

	/* make sure we're capturing on an Ethernet device */
	//pcap_datalink() must not be called on a pcap  descriptor  created  by  pcap_create()
    //  that has not yet been activated by pcap_activate().
	if (pcap_datalink( pcap ) != DLT_EN10MB) {
		log_write( LOG_ERR, "'%s' is not an Ethernet. (be sure that you are running probe with root permission)\n",
				context->config->input->input_source);
		exit( EXIT_FAILURE );
	}

	context->modules.pcap->handler = pcap;


	//start processing

	//-1: unlimited number of packets to capture.
	//this loop is ended when:
	//- then end of pcap file, or,
	//- pcap_breakloop() is called, or,
	//- an error
	pcap_loop( pcap, -1, got_a_packet, (u_char*) context );
}


