/*
 * pcap_capture.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
 */

#ifndef PCAP_MODULE
#define PCAP_MODULE
#endif

#include <pthread.h>
#include <pcap.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>

#include "../../../lib/ms_timer.h"
#include "../../../worker.h"
#include "data_spsc_ring.h"

#define BREAK_PCAP_NUMBER 0

#include "pcap_capture.h"
#include <tcpip/mmt_tcpip.h>

//for one thread
struct pcap_worker_context_struct{
	pthread_t thread_handler;
	data_spsc_ring_t fifo;
};

//for all application
struct pcap_probe_context_struct{
	pcap_t *handler;
};


//naif: do nothing
//#define hash( x ) x

//Knuth's multiplicative method:
//#define hash( i ) (i*2654435761 >> 8 )

//http://stackoverflow.com/a/12996028/1069256
static inline uint32_t hash(uint32_t x) {
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = ((x >> 16) ^ x) * 0x45d9f3b;
    x = (x >> 16) ^ x;
    return x;
}

/**
 * Hash function of an IP packet. The function give a hash number to represent
 *   a tuple (IP-src, Port-src, IP-dst, Port-dst).
 * This hash function must be symmetric, that is,
 * (IP-src, Port-src, IP-dst, Port-dst) and (IP-dst, Port-dst, IP-src, Port-src) must have the same hash number.
 * Two different tuples may get the same hash number, but a tuple must give only one hash number.
 */
static inline uint32_t _get_packet_hash_number( const uint8_t *packet, size_t pkt_len ){
	static int id = 0;
	//Ethernet structure
	struct __ethernet_struct {
		uint8_t src[6];
		uint8_t dst[6];
		uint16_t proto;
	} *eth;

	uint32_t ip_src, ip_dst;
	uint16_t port_src, port_dst;
	uint16_t ip_offset;
	uint8_t proto_id; //ID of protocol after IP

	if ( unlikely( pkt_len < 38))
		return 0; //TODO: this is not elegant check IP, IPv6 etc.

	eth = (struct __ethernet_struct *) packet;


	switch( eth->proto ){
	//IP
	case 0x08:
		ip_offset = 26;
		break;
	//vlan
	case 0x81:
		ip_offset = 30;
		break;
	default:
		//for other protocol
		return 0;
	}

	ip_src = *((uint32_t *) &packet[ ip_offset     ]);
	ip_dst = *((uint32_t *) &packet[ ip_offset + 4 ]);
//
	proto_id = *((uint8_t *) &packet[ ip_offset - 3 ]);
	//src and dst ports of TCP or UDP
	if( likely(proto_id == 6 || proto_id == 17 )){
		port_src = *((uint16_t *) &packet[ ip_offset + 8]);
		port_dst = *((uint16_t *) &packet[ ip_offset + 8 + 2]);
	}
	else
		port_dst = port_src = 0;

	//naif symmetric hash function
	uint32_t hash_number = (ip_src | ip_dst ) |  ( port_src | port_dst );
	//try to get uniform distribution
	hash_number = hash( hash_number );

//	DEBUG("%4d %s %03d.%03d.%03d.%03d:%d -> %03d.%03d.%03d.%03d:%d == %u",
//			++id,
//			(proto_id == 6 )? "TCP" : "UDP",
//			((ip_src << 24) >> 24), ((ip_src << 16) >> 24), ((ip_src << 8) >> 24), (ip_src >> 24),
//			ntohs( port_src ),
//			((ip_dst << 24) >> 24), ((ip_dst << 16) >> 24), ((ip_dst << 8) >> 24), (ip_dst >> 24),
//			ntohs( port_dst ),
//			hash
//	);
//
	return hash_number;
}

//worker thread
static void *_worker_thread( void *arg){
	worker_context_t *worker_context = (worker_context_t*) arg;
	data_spsc_ring_t *fifo = &worker_context->pcap->fifo;
	const probe_conf_t *config = worker_context->probe_context->config;
	uint32_t fifo_tail_index;
	pkthdr_t *pkt_header;
	const u_char *pkt_data;
	int i, avail_pkt_count;


	//move this thread to a specific processor
	long avail_processors = mmt_probe_get_number_of_online_processors();
	if( avail_processors > 1 ){
		avail_processors -= 1;//avoid zero that is using by Reader
		(void) move_the_current_thread_to_a_core( worker_context->index % avail_processors + 1, -10 );
	}

	worker_on_start( worker_context );


	struct timeval now; //current timestamp that is either
				//- real timestamp of system when running online
	 	 	 	//- packet timestamp when running offline

	while( true ){
		//get number of packets being available
		avail_pkt_count = data_spsc_ring_pop_bulk( fifo, &fifo_tail_index );

		/* if no packet has arrived  */
		if ( avail_pkt_count <= 0 ) {

			//we do not use packet timestamp for online analysis as
			// there may be exist some moment having no packets => output will be blocked until a new packet comes
			//get the current timestamp of system
			if( config->input->input_mode == ONLINE_ANALYSIS )
				gettimeofday( &now, NULL );
			worker_update_timer( worker_context, &now );

			//=> sleep 100 micro-second
			nanosleep( (const struct timespec[]){{0, 100000L}}, NULL );
		} else {  /* else remove number of packets from list and process it */

			//the last packet will be verified after (not in for)
			avail_pkt_count --;
			for( i=0; i<avail_pkt_count; i++ ){
				pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, i + fifo_tail_index);
				pkt_data   = (u_char *)(pkt_header + 1);
				worker_process_a_packet( worker_context, pkt_header, pkt_data );

				worker_update_timer( worker_context, &pkt_header->ts );
			}

			//only the last packet in the queue may has NULL data
			pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, avail_pkt_count + fifo_tail_index);

			/* is it a dummy packet ? => means that the worker thread must exit */
			if( unlikely( pkt_header->len == BREAK_PCAP_NUMBER ))
				break;
			else{
				now = pkt_header->ts;
				worker_process_a_packet( worker_context, pkt_header, (u_char *)(pkt_header + 1) );
				worker_update_timer( worker_context, &pkt_header->ts );
			}

			//update new position of ring's tail => give place to a new packet
			data_spsc_ring_update_tail( fifo, fifo_tail_index, avail_pkt_count + 1);
		}
	}

	worker_on_stop( worker_context );
	//exit thread
	return NULL;
}

static inline void _got_a_packet_smp( u_char* user, const struct pcap_pkthdr *pcap_header, const u_char *pcap_data){
	probe_context_t *context =( probe_context_t *)user;

	//multithreading

	//dispatch a packet basing on its hash number
	uint32_t pkt_index = _get_packet_hash_number(pcap_data, pcap_header->caplen );
	pkt_index %= context->config->thread->thread_count;

	//get context to the corresponding worker
	// then push packet into fifo of the worker
	worker_context_t *worker_context = context->smp[ pkt_index ];

	pkthdr_t *pkt_header;
	//get available space to put the packet into
	data_spsc_ring_get_tmp_element( &worker_context->pcap->fifo,  (void**) &pkt_header );

	/* fill smp_pkt fields and copy packet data from pcap buffer */
	pkt_header->len       = pcap_header->len;
	pkt_header->caplen    = pcap_header->caplen;
	pkt_header->ts        = pcap_header->ts;
	pkt_header->user_args = NULL;
	//put data in the same memory segment but after sizeof( pkt )
	void *pkt_data    =  pkt_header + 1;
	memcpy( pkt_data, pcap_data, pcap_header->caplen );

	//queue is full??
	while(  unlikely( data_spsc_ring_push_tmp_element( &worker_context->pcap->fifo ) != QUEUE_SUCCESS )){
		//in offline mode, we must not reject a packet when queue is full
		// but we need to wait until we can insert the packet into queue
		if( context->config->input->input_mode == OFFLINE_ANALYSIS )
			nanosleep( (const struct timespec[]){{ .tv_sec = 0, .tv_nsec = 100000L}}, NULL );
		else{
			//in online mode, we drop the packet
			worker_context->stat.pkt_dropped ++;
			return;
		}
	}
}

static inline void _print_traffic_statistics( const ms_timer_t *timer, void *arg ){
	struct pcap_stat pcs; //packet capture stats
	struct timeval tv;
	probe_context_t *context = arg;

	if( context->config->input->input_mode != ONLINE_ANALYSIS )
		return;

	//get statistics from libpcap
	if (pcap_stats(context->modules.pcap->handler, &pcs) < 0) {
		log_write_dual( LOG_WARNING, "Cannot get statistics from pcap: %s", pcap_geterr( context->modules.pcap->handler ));
	}else{
		context->traffic_stat.nic.receive = pcs.ps_recv;
		context->traffic_stat.nic.drop    = pcs.ps_ifdrop + pcs.ps_drop;
	}

	gettimeofday( &tv, NULL );
	context_print_traffic_stat( context, &tv );
}

//this function is called only in single-thread mode to process packets
static void _got_a_packet(u_char* user, const struct pcap_pkthdr *pcap_header, const u_char *pcap_data){
	probe_context_t *context   = ( probe_context_t *)user;
	const probe_conf_t *config = context->config;
	struct timeval now;
	//when having packet data to process
	if( pcap_data != NULL ){
		if( IS_SMP_MODE( context )){
			_got_a_packet_smp(user, pcap_header, pcap_data);
		}else{
			pkthdr_t pkt_header;
			//convert from pcap's header to mmt packet's header
			pkt_header.ts        = pcap_header->ts;
			pkt_header.caplen    = pcap_header->caplen;
			pkt_header.len       = pcap_header->len;
			pkt_header.user_args = NULL;

			worker_process_a_packet( context->smp[0], &pkt_header, pcap_data );
		}

		now = pcap_header->ts;

		context->traffic_stat.mmt.bytes.receive += pcap_header->len;
		context->traffic_stat.mmt.packets.receive ++;
	}

	//call worker timer only in non-smp mode
	//because in SMP mode, the timers will be updated inside _worker_thread
	if( IS_SMP_MODE( context ))
		return;

	//we do not use packet timestamp for online analysis as
	// there may be exist some moment having no packets => output will be blocked until a new packet comes
	//get the current timestamp of system
	if( config->input->input_mode == ONLINE_ANALYSIS )
		gettimeofday( &now, NULL );


	worker_context_t *worker_context = context->smp[0];
	worker_update_timer( worker_context, &now );
}

//this function is called by main thread when user press Ctrl+C
void pcap_capture_stop( probe_context_t *context ){
	//stop processing packets by breaking pcap_loop()
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_AFTER( &( context->modules.pcap->handler ) ));
	pcap_breakloop( context->modules.pcap->handler );
}


static inline void _print_pcap_stats( const probe_context_t *context ){
	struct pcap_stat pcs; //packet capture stats

	//get statistics from pcap
	if( context->config->input->input_mode == ONLINE_ANALYSIS ){
		if (pcap_stats(context->modules.pcap->handler, &pcs) < 0) {
			log_write_dual( LOG_WARNING, "Cannot get statistics from pcap: %s", pcap_geterr( context->modules.pcap->handler ));
		}else{
			u_int pkt_received = pcs.ps_recv;
			u_int pkt_dropped  = pcs.ps_ifdrop + pcs.ps_drop;
			log_write_dual( LOG_INFO, "System received %d packets, dropped %d (%.2f%% = %.2f%% by NIC + %.2f%% by kernel)",
					pkt_received,
					pkt_dropped,
					pkt_dropped   * 100.0 / pkt_received,
					pcs.ps_ifdrop * 100.0 / pkt_received,
					pcs.ps_drop   * 100.0 / pkt_received);
		}
	}
}

/**
 * Release pcap context
 * @param context
 */
static inline void _pcap_capture_release( probe_context_t *context ){
	int i;
	//close pcap in main thread
	pcap_close( context->modules.pcap->handler );
	context->modules.pcap->handler = NULL;

	//release resources of each worker
	int workers_count;
	if( IS_SMP_MODE( context ) )
		workers_count = context->config->thread->thread_count;
	else
		workers_count = 1;

	for( i=0; i<workers_count; i++ ){
		if( IS_SMP_MODE( context ) ){
			data_spsc_ring_free( & context->smp[i]->pcap->fifo );
		}

		mmt_probe_free( context->smp[i]->pcap );
		worker_release( context->smp[i] );
	}

	mmt_probe_free( context->smp );
	mmt_probe_free( context->modules.pcap );
}



//public API
void pcap_capture_start( probe_context_t *context ){
	int i, ret;
	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	pcap_t *pcap;
	ms_timer_t traffic_stat_report_timer;
	struct timeval now_tv;

	int workers_count;
	if( IS_SMP_MODE( context )){
		log_write( LOG_INFO, "Starting PCAP mode to analyze '%s' using %d thread(s)",
			context->config->input->input_source,
			context->config->thread->thread_count );
		//each worker will run on a separate thread
		//the main thread will be used to read packets
		workers_count = context->config->thread->thread_count;
	}else{
		log_write( LOG_INFO, "Starting PCAP mode to analyze '%s' using the main thread",
				context->config->input->input_source );
		//this worker will run on the main thread
		workers_count = 1;
	}

	//memory for the pcap module
	context->modules.pcap = mmt_alloc_and_init_zero( sizeof( struct pcap_probe_context_struct ));

	//allocate context for each thread
	context->smp = mmt_alloc_and_init_zero( sizeof( worker_context_t ) * workers_count );

	//allocate and initialize memory for each worker
	for( i=0; i<workers_count; i++ ){
		context->smp[i] = worker_alloc_init( context->config->stack_type );
		//when there is only one thread (no SMP mode)
		// => reuse the same output of the main program
		if( !IS_SMP_MODE( context ))
			context->smp[i]->output = context->output;

		context->smp[i]->index = i;

		//keep a reference to its root
		context->smp[i]->probe_context = context;


		//specific for pcap module
		context->smp[i]->pcap = mmt_alloc_and_init_zero( sizeof( struct pcap_worker_context_struct ));

		//pthread_spin_init( & context->smp[i]->pcap->spin_lock, PTHREAD_PROCESS_PRIVATE);

		//initialize in case of multi-threading
		if( IS_SMP_MODE( context ) ){
			//a spsc buffer shared between a worker and the main thread
			if( data_spsc_ring_init( &context->smp[i]->pcap->fifo,
					context->config->thread->thread_queue_packet_threshold,
					//one element to contains packet: header + data
					(sizeof( pkthdr_t ) + context->config->input->snap_len)
			)){

				ABORT( "Cannot allocate FIFO buffer for thread %d. Please reduce thread-queue or thread-nb",
						i);
			}

			//start worker thread
			pthread_create( &context->smp[i]->pcap->thread_handler, NULL,
					_worker_thread, context->smp[i] );
		}
		else
			//when there is only one worker running on the main thread
			worker_on_start( context->smp[0] );
	}

	if( context->config->input->input_mode == OFFLINE_ANALYSIS ){
		pcap = pcap_open_offline( context->config->input->input_source, errbuf );
		ASSERT( pcap != NULL,
				"Couldn't open file %s\n", errbuf);
	}else{
		/* open capture device */
		pcap = pcap_create(context->config->input->input_source, errbuf);
		ASSERT( pcap != NULL ,
				"Couldn't open device \'%s\': %s\n",
					context->config->input->input_source,
					errbuf);

		//set IP packet size
		if( context->config->input->snap_len ){
			log_write( LOG_DEBUG, "Set snap-len for pcap capture: %"PRIu16, context->config->input->snap_len);
			ret = pcap_set_snaplen( pcap, context->config->input->snap_len );
			ASSERT( ret == 0,
				"Cannot set snaplen for pcap capture: %d", context->config->input->snap_len );
		}
		//put NIC to promiscuous mode to capture any packets
		ret = pcap_set_promisc( pcap, 1);
		ASSERT( ret == 0 ,
				"Cannot put '%s' NIC to promiscuous mode",
					context->config->input->input_source );
		if( context->config->input->timeout ){
			log_write( LOG_DEBUG, "Set timeout for pcap capture: %"PRIu32, context->config->input->timeout);
			ret = pcap_set_timeout( pcap, context->config->input->timeout);
			ASSERT( ret == 0, "Cannot set zero timeout for pcap capture: %"PRIu32, context->config->input->timeout);
		}

		//buffer size
		if( context->config->input->buffer_size ){
			log_write( LOG_DEBUG, "Set buffer-size for pcap capture: %"PRIu32, context->config->input->buffer_size);
			ret = pcap_set_buffer_size(pcap, context->config->input->buffer_size);
			ASSERT( ret == 0, "Cannot set buffer for pcap capture: %"PRIu32, context->config->input->buffer_size);
		}

		ret = pcap_activate(pcap);
		ASSERT( ret == 0,
				"Cannot activate pcap capture: %s", pcap_geterr( pcap ) );

		/* make sure we're capturing on an Ethernet device */
		//pcap_datalink() must not be called on a pcap  descriptor  created  by  pcap_create()
		//  that has not yet been activated by pcap_activate().
		ret = pcap_datalink( pcap );
		if( ret == 1 && (context->config->stack_type != 1 && context->config->stack_type != PROTO_ETHERNET))
			log_write( LOG_INFO, "Detect LINKTYPE_ETHERNET on %s but you are using stack-type=%d. The classification might be incorrect.",
					context->config->input->input_source,
					context->config->stack_type);
		else if( ret != context->config->stack_type )
			log_write( LOG_INFO, "Stack type of '%s is %d (while you are using 'stack-type=%d'). The classification might be incorrect.",
					context->config->input->input_source,
					ret,
					context->config->stack_type);
	}

	context->modules.pcap->handler = pcap;

	ret = 0;
	//set in non-blocking mode in case of no threading
	// we need non-blocking mode in order to not be blocked when there are no packets.
	// This allows us to periodically output reports to files/mongodb/...
	if( context->config->input->input_mode != OFFLINE_ANALYSIS ){
		ret = pcap_setnonblock(pcap, true, errbuf );
		if( ret == -1 )
			ABORT("Cannot put pcap in non-blocking mode: %s", errbuf );
	}

	ms_timer_init( &traffic_stat_report_timer, context->config->stat_period * S2MS,
			_print_traffic_statistics, context );


	while( ! context->is_exiting ){
		//-1: unlimited number of packets to capture.
		ret = pcap_dispatch( pcap, -1, _got_a_packet, (u_char*) context );
		//			0 if no packets were read from  a  live  capture  (if,  for
		//			       example,  they  were discarded because they didn't pass the packet filter
		//			       or if, on platforms that support a read timeout that starts before
		//			       any  packets  arrive, the timeout expires before any packets arrive, or
		//			       if the file descriptor for the capture device is in  non-blocking  mode
		//			       and  no  packets  were  available to be read)
		//          			or if no more packets are available in a ``savefile.''
		//			-1 if an error occurs
		//			-2 if  the  loop terminated due to a call to pcap_breakloop()
		//				 before any packets were processed.
		if( ret == 0 ){
			//if no more packets are available in a ``savefile.''
			if( context->config->input->input_mode == OFFLINE_ANALYSIS )
				break;
			else{
				//we still call this function, even there is no packet, to processing timeout functions,
				// such as, worker_on_timer_stat_period, worker_on_timer_sample_file_period
				_got_a_packet( (u_char*) context, NULL, NULL );
				//we need to small sleep here to wait for a new packet
				nanosleep( (const struct timespec[]){{0, 100000L}}, NULL );
			}
		}else if( ret > 0 )
			continue;
		else
			break;

		gettimeofday( &now_tv, NULL );
		ms_timer_set_time(&traffic_stat_report_timer, &now_tv);
	}

	switch( ret ){
	case 0: //no more packets are available
		log_write( LOG_INFO, "Normally reached to the end of pcap file" );
		break;
	case -1:// if an error occurs
		log_write( LOG_ERR, "Error when reading pcap: %s", pcap_geterr( pcap ));
		break;
	case -2: // if the loop terminated due to a call to pcap_breakloop() before any packets were processed.
		log_write( LOG_INFO, "pcap_breakloop() is called" );
		break;
	default:
		log_write( LOG_INFO, "Exit with pcap value: %d", ret );
	}

	//stop all workers
	if( IS_SMP_MODE( context ) ){
		pkthdr_t *pkt_header;

		//send empty message to each thread to tell them to stop
		for( i=0; i<context->config->thread->thread_count; i++ ){
			data_spsc_ring_get_tmp_element( &context->smp[i]->pcap->fifo,  (void **)(&pkt_header) );
			pkt_header->len = BREAK_PCAP_NUMBER;

			//queue is full??
			while(  unlikely( data_spsc_ring_push_tmp_element( &context->smp[i]->pcap->fifo ) != QUEUE_SUCCESS )){
				//we need to wait until we can insert the dummy packet into queue
				nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
			}
		}

		//waiting for all workers finish their jobs
		for( i=0; i<context->config->thread->thread_count; i++ ){
			ret = pthread_join( context->smp[i]->pcap->thread_handler, NULL );
			if( ret != 0 ){
				log_write( LOG_ERR, "Cannot stop worker %d: %s", i, strerror( errno ) );
				continue;
			}
		}
	}
	else{
		//when there is only one worker running on the main thread
		worker_on_stop( context->smp[0] );
	}

	worker_print_common_statistics( context );

	_print_pcap_stats( context );

	//all workers have been stopped
	_pcap_capture_release( context );
}


