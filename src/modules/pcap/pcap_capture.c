/*
 * pcap_capture.h
 *
 *  Created on: Dec 13, 2017
 *      Author: nhnghia
 */



#include <pthread.h>
#include <pcap.h>


#include "pcap_capture.h"
#include "../../lib/alloc.h"
#include "../../lib/processing.h"
#include "../../lib/system_info.h"
#include "data_spsc_ring.h"



//for one thread
struct pcap_single_thread_context_struct{
	pthread_t thread_handler;
	pthread_spinlock_t spin_lock;
	data_spsc_ring_t fifo;
	probe_context_t *probe_context;
};

//for all application
struct pcap_context_struct{
	pcap_t *handler;
};


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

//worker thread
static void *_worker_thread( void *arg){
	single_thread_context_t *worker_context = (single_thread_context_t*) arg;
	probe_context_t *probe_context = worker_context->pcap->probe_context;
	data_spsc_ring_t *fifo = &worker_context->pcap->fifo;
	uint32_t fifo_tail_index;
	pkthdr_t *pkt_header;
	const u_char *pkt_data;
	int i, avail_pkt_count;


	//move this thread to a specific processor
	long avail_processors = get_number_of_online_processors();
	if( avail_processors > 1 ){
		avail_processors -= 1;//avoid zero that is using by Reader
		(void) move_the_current_thread_to_a_core( worker_context->index % avail_processors + 1, -10 );
	}

	while( true ){
		//get number of packets being available
		avail_pkt_count = data_spsc_ring_pop_bulk( fifo, &fifo_tail_index );

		/* if no packet has arrived sleep 1 milli-second */
		if ( avail_pkt_count <= 0 ) {
			select(0, NULL, NULL, NULL, (struct timeval[]){{.tv_sec = 0, .tv_usec = 1000}});
			//nanosleep( (const struct timespec[]){{0, 1000000L}}, NULL );
		} else {  /* else remove number of packets from list and process it */
			//the last packet will be verified after (not in for)
			avail_pkt_count --;
			for( i=0; i<avail_pkt_count; i++ ){
				pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, i + fifo_tail_index);
				pkt_data   = (u_char *)(pkt_header + 1);
				packet_processing( worker_context, pkt_header, pkt_data );
			}

			//only the last packet in the queue may has NULL data
			pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, avail_pkt_count + fifo_tail_index);

			/* is it a dummy packet ? => means thread must exit */
			if( unlikely( pkt_header->caplen == 0 && pkt_header->len == 0 ))
				break;
			else{
				packet_processing( worker_context, pkt_header, (u_char *)(pkt_header + 1) );
			}

			//update new position of ring's tail
			data_spsc_ring_update_tail( fifo, fifo_tail_index, avail_pkt_count + 1); //+1 as avail_pkt_count-- above
		}
	}

	//exit thread
	pthread_exit( NULL );
	return NULL;
}

static void _got_a_packet(u_char* user, const struct pcap_pkthdr *pcap_header, const u_char *pcap_data){
	probe_context_t *context =( probe_context_t *)user;

	if( !IS_SMP_MODE( context ) ){
		pkthdr_t header;

		//convert from pcap's header to mmt packet's header
		header.ts        = pcap_header->ts;
		header.caplen    = pcap_header->caplen;
		header.len       = pcap_header->len;
		header.user_args = NULL;

		packet_processing(context->smp[0], &header, pcap_data );
	}else{
		//multithreading
		uint32_t pkt_index = _get_packet_hash_number(pcap_data, pcap_header->caplen ) % context->config->thread->thread_count;
		//printf("%d\n", pkt_index);
		//get context to the corresponding worker
		// then push packet into fifo of the worker
		single_thread_context_t *worker_context = context->smp[ pkt_index ];

		pkthdr_t *header;
		//get available space to put the packet into
		data_spsc_ring_get_tmp_element( &worker_context->pcap->fifo,  (void**) &header );

		/* fill smp_pkt fields and copy packet data from pcap buffer */
		header->len       = pcap_header->len;
		header->caplen    = pcap_header->caplen;
		header->ts        = pcap_header->ts;
		header->user_args = NULL;
		//put data in the same memory segment but after sizeof( pkt )
		void *pkt_data    =  header + 1;
		memcpy( pkt_data, pcap_data, header->caplen);

		//queue is full??
		while(  unlikely( data_spsc_ring_push_tmp_element( &worker_context->pcap->fifo ) != QUEUE_SUCCESS )){
			//in offline mode, we must not reject a packet when queue is full
			// but we need to wait until we can insert the packet into queue
			if( context->config->input->input_mode == OFFLINE_ANALYSIS )
				nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
			else
				worker_context->stat.pkt_dropped ++;
		}
	}
}

//this function is called by main thread when user press Ctrl+C
void pcap_capture_stop( probe_context_t *context ){
	struct pcap_stat pcs; //packet capture stats
	int i;
	pkthdr_t *pkt_header;
	//stop processing packets
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_AFTER( &( context->modules.pcap->handler ) ));
	pcap_breakloop( context->modules.pcap->handler );


	//waiting for all workers finish their jobs
	if( IS_SMP_MODE( context ) ){
		//send empty message to each thread to tell them to stop
		for( i=0; i<context->config->thread->thread_count; i++ ){
			data_spsc_ring_get_tmp_element( &context->smp[i]->pcap->fifo,  (void **)(&pkt_header) );
			pkt_header->caplen = 0;
			pkt_header->len    = 0;

			//queue is full??
			while(  unlikely( data_spsc_ring_push_tmp_element( &context->smp[i]->pcap->fifo ) != QUEUE_SUCCESS )){
				//we need to wait until we can insert the dummy packet into queue
				nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
			}
		}

		for( i=0; i<context->config->thread->thread_count; i++ ){
			pthread_join( context->smp[i]->pcap->thread_handler, NULL );
		}
	}
}

//PUBLIC API
void pcap_capture_release( probe_context_t *context ){
	struct pcap_stat pcs; //packet capture stats
	int i;

	//get statistics from pcap
	if( context->config->input->input_mode == ONLINE_ANALYSIS ){
		if (pcap_stats(context->modules.pcap->handler, &pcs) < 0) {
			log_write( LOG_WARNING, "Cannot get statistics from pcap: %s", pcap_geterr( context->modules.pcap->handler ));
		}else{
			u_int pkt_received = pcs.ps_recv;
			u_int pkt_dropped  = pcs.ps_ifdrop + pcs.ps_drop;
			log_write( LOG_INFO, "System received %d packets, dropped %d (%.2f%% = %.2f%% by NIC + %.2f%% by kernel)",
					pkt_received,
					pkt_dropped,
					pkt_dropped   * 100.0 / pkt_received,
					pcs.ps_ifdrop * 100.0 / pkt_received,
					pcs.ps_drop   * 100.0 / pkt_received);
		}
	}

	//close pcap in main thread
	pcap_close( context->modules.pcap->handler );
	context->modules.pcap->handler = NULL;

	//release resources of each thread
	for( i=0; i<context->config->thread->thread_count; i++ ){
		if( IS_SMP_MODE( context ) ){
			data_spsc_ring_free( & context->smp[i]->pcap->fifo );
		}

		xfree( context->smp[i]->pcap );
		xfree( context->smp[i] );
	}

	xfree( context->modules.pcap );
}



//public API
void pcap_capture_start( probe_context_t *context ){
	int i, ret;
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	pcap_t *pcap;

	log_write( LOG_INFO, "Starting PCAP mode to analyze '%s' using %d thread(s)",
			context->config->input->input_source,
			context->config->thread->thread_count );

	context->modules.pcap = alloc( sizeof( struct pcap_context_struct ));

	for( i=0; i<context->config->thread->thread_count; i++ ){
		context->smp[i] = alloc_init_single_thread_context_t();

		context->smp[i]->index = i;

		//specific for pcap module
		context->smp[i]->pcap = alloc( sizeof( struct pcap_single_thread_context_struct ));

		//init ..

		//keep a reference to its root
		context->smp[i]->pcap->probe_context = context;
		pthread_spin_init( & context->smp[i]->pcap->spin_lock, PTHREAD_PROCESS_PRIVATE);

		//multi-threading
		if( IS_SMP_MODE( context ) ){
			if( data_spsc_ring_init( &context->smp[i]->pcap->fifo,
					context->config->thread->thread_queue_packet_threshold,
					//one element to contains packet: header + data
					(sizeof( pkthdr_t ) + context->config->input->snap_len)
			)){

				log_write(LOG_ERR, "Cannot allocate FIFO buffer for thread %d. Please reduce thread-queue or thread-nb",
						i);
				exit( EXIT_FAILURE );
			}

			//start worker thread
			pthread_create( &context->smp[i]->pcap->thread_handler, NULL,
					_worker_thread, context->smp[i] );
		}
	}

	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		pcap = pcap_open_offline( context->config->input->input_source, errbuf );
		if( pcap == NULL ){
			log_write( LOG_ERR, "Couldn't open file \'%s\': %s\n",
					context->config->input->input_source,
					errbuf);
			exit( EXIT_FAILURE );
		}
	}else{
		/* open capture device */
		pcap = pcap_create(context->config->input->input_source, errbuf);
		if ( pcap == NULL ) {
			log_write( LOG_ERR, "Couldn't open device \'%s\': %s\n",
					context->config->input->input_source,
					errbuf);
			exit( EXIT_FAILURE );
		}

		//set IP packet size
		ret = pcap_set_snaplen( pcap, context->config->input->snap_len );
		//put NIC to promiscuous mode to capture any packets
		ret = pcap_set_promisc( pcap, 1);
		if( ret != 0 ){
			log_write( LOG_ERR, "Cannot put '%s' NIC to promiscuous mode", context->config->input->input_source);
			exit( EXIT_FAILURE );
		}
		ret = pcap_set_timeout( pcap, 0 );
		//buffer size
		pcap_set_buffer_size(pcap, 500*1000*1000);
		pcap_activate(pcap);

		/* make sure we're capturing on an Ethernet device */
		//pcap_datalink() must not be called on a pcap  descriptor  created  by  pcap_create()
		//  that has not yet been activated by pcap_activate().
		if (pcap_datalink( pcap ) != DLT_EN10MB) {
			log_write( LOG_ERR, "'%s' is not an Ethernet. (be sure that you are running probe with root permission)\n",
					context->config->input->input_source);
			exit( EXIT_FAILURE );
		}
	}

	context->modules.pcap->handler = pcap;


	//start processing

	//-1: unlimited number of packets to capture.
	//this loop is ended when:
	//- then end of pcap file, or,
	//- pcap_breakloop() is called, or,
	//- an error
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_BEFORE( &( pcap ) ));
	pcap_loop( pcap, -1, _got_a_packet, (u_char*) context );
}


