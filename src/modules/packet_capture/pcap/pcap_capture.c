/*
 * pcap_capture.h
 *
 *  Created on: Dec 13, 2017
 *          by: Huu Nghia
 */



#include <pthread.h>
#include <pcap.h>
#include <time.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>

#include "../../../worker.h"
#include "data_spsc_ring.h"

#define BREAK_PCAP_NUMBER 0

#ifndef PCAP_MODULE
#define PCAP_MODULE
#endif

#include "pcap_capture.h"

//for one thread
struct pcap_worker_context_struct{
	pthread_t thread_handler;
	data_spsc_ring_t fifo;
};

//for all application
struct pcap_probe_context_struct{
	pcap_t *handler;
};

#define MICRO_SECOND 1000000

/**
 * This function is called only in **single thread function mode**
 * @param signal
 */
static void _alarm_handler( int signal ){
	extern probe_context_t context;
	static size_t stat_period_counter = 0, output_to_file_period_counter = 0;

	struct timeval start_time, end_time;
	gettimeofday( &start_time, NULL );

	if( context.config->outputs.file->is_sampled && context.config->outputs.file->is_enable ){
		output_to_file_period_counter ++;
		if( output_to_file_period_counter == context.config->outputs.cache_period ){
			worker_on_timer_sample_file_period( context.smp[0] );
			//reset counter
			output_to_file_period_counter = 0;
		}
	}

	//increase 1 second;
	stat_period_counter ++;
	if( stat_period_counter == context.config->stat_period ){
		worker_on_timer_stat_period( context.smp[0] );
		//reset counter
		stat_period_counter = 0;
	}

	//calculate the rest of one second after executed the functions above
	gettimeofday( &end_time, NULL );
	size_t usecond = (end_time.tv_sec - start_time.tv_sec)*MICRO_SECOND + (end_time.tv_usec - start_time.tv_usec );

	if( usecond >= MICRO_SECOND ){
		log_write( LOG_ERR, "Too slow interval processing" );
		_alarm_handler( SIGALRM );
		return;
	}

	DEBUG("next iterate in %zu us", MICRO_SECOND - usecond);

	//call this handler again
	if( usecond == 0 )
		alarm( 1 ); //ualarm cannot be used for interval >= 1 second
	else
		ualarm( MICRO_SECOND - usecond, 0 );
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
	uint16_t ip_off;

	if ( unlikely( pkt_len < 38))
		return 0; //TODO: this is not elegant check IP, IPv6 etc.

	eth = (struct __ethernet_struct *) packet;


	switch( eth->proto ){
	//IP
	case 0x08:
		ip_off = 26;
		break;
	//vlan
	case 0x81:
		ip_off = 30;
		break;
	default:
		//for other protocol
		return 0;
	}

	a1 = *((uint32_t *) &packet[ ip_off     ]);
	a2 = *((uint32_t *) &packet[ ip_off + 4 ]);
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
	worker_context_t *worker_context = (worker_context_t*) arg;
	probe_context_t *probe_context = worker_context->probe_context;
	data_spsc_ring_t *fifo = &worker_context->pcap->fifo;
	const probe_conf_t *config = worker_context->probe_context->config;
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

	worker_on_start( worker_context );


	time_t next_stat_ts = 0; //moment we need to do statistic
	time_t next_output_ts = 0; //moment we need flush output to channels
	time_t now = 0; //current timestamp that is either
				//- real timestamp of system when running online
	 	 	 	//- packet timestamp when running offline

	while( true ){
		//get number of packets being available
		avail_pkt_count = data_spsc_ring_pop_bulk( fifo, &fifo_tail_index );

		/* if no packet has arrived => sleep 1 milli-second */
		if ( avail_pkt_count <= 0 ) {
			nanosleep( (const struct timespec[]){{0, 10000L}}, NULL );
		} else {  /* else remove number of packets from list and process it */

			//the last packet will be verified after (not in for)
			avail_pkt_count --;
			for( i=0; i<avail_pkt_count; i++ ){
				pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, i + fifo_tail_index);
				pkt_data   = (u_char *)(pkt_header + 1);
				worker_process_a_packet( worker_context, pkt_header, pkt_data );
			}

			//only the last packet in the queue may has NULL data
			pkt_header = (pkthdr_t *) data_spsc_ring_get_data( fifo, avail_pkt_count + fifo_tail_index);

			/* is it a dummy packet ? => means that the worker thread must exit */
			if( unlikely( pkt_header->len == BREAK_PCAP_NUMBER ))
				break;
			else{
				now = pkt_header->ts.tv_sec;

				worker_process_a_packet( worker_context, pkt_header, (u_char *)(pkt_header + 1) );
			}

			//update new position of ring's tail => give place to a new packet
			data_spsc_ring_update_tail( fifo, fifo_tail_index, avail_pkt_count + 1);
		}

		//we do not use packet timestamp for online analysis as
		// there may be exist some moment having no packets => output will be blocked until a new packet comes
		//get the current timestamp of system
		if( config->input->input_mode == ONLINE_ANALYSIS )
			now = time( NULL );

		//first times: we need to initialize the 2 milestones
		if( next_output_ts == 0 && now != 0 ){
			next_stat_ts = now + config->stat_period;
			next_output_ts = now + config->outputs.cache_period;
		}else{
			//statistic periodically
			if( now > next_stat_ts  ){
				next_stat_ts += config->stat_period;
				//call worker
				worker_on_timer_stat_period( worker_context );
			}

			//if we need to sample output file
			if( config->outputs.file->is_sampled && now >  next_output_ts ){
				next_output_ts += config->outputs.cache_period;
				//call worker
				worker_on_timer_sample_file_period( worker_context );
			}
		}
	}

	worker_on_stop( worker_context );
	//exit thread
	pthread_exit( NULL );
	return NULL;
}

static void _got_a_packet(u_char* user, const struct pcap_pkthdr *pcap_header, const u_char *pcap_data){
	probe_context_t *context =( probe_context_t *)user;

	if( !IS_SMP_MODE( context ) ){
		pkthdr_t pkt_header;

		//convert from pcap's header to mmt packet's header
		pkt_header.ts        = pcap_header->ts;
		pkt_header.caplen    = pcap_header->caplen;
		pkt_header.len       = pcap_header->len;
		pkt_header.user_args = NULL;

		worker_process_a_packet( context->smp[0], &pkt_header, pcap_data );
	}else{
		//multithreading

		//dispatch a packet basing on its hash number
		uint32_t pkt_index = _get_packet_hash_number(pcap_data, pcap_header->caplen );
		pkt_index %= context->config->thread->thread_count;
		//printf("%d\n", pkt_index);
		//return;

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
				nanosleep( (const struct timespec[]){{ .tv_sec = 0, .tv_nsec = 10000L}}, NULL );
			else
				worker_context->stat.pkt_dropped ++;
		}
	}
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

	int workers_count = 1;
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
	context->smp = mmt_alloc( sizeof( worker_context_t ) * workers_count );

	//allocate and initialize memory for each worker
	for( i=0; i<workers_count; i++ ){
		context->smp[i] = worker_alloc_init();

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

				log_write(LOG_ERR, "Cannot allocate FIFO buffer for thread %d. Please reduce thread-queue or thread-nb",
						i);
				exit( EXIT_FAILURE );
			}

			//start worker thread
			pthread_create( &context->smp[i]->pcap->thread_handler, NULL,
					_worker_thread, context->smp[i] );
		}
		else
			//when there is only one worker running on the main thread
			worker_on_start( context->smp[i] );
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
			log_write( LOG_ERR, "Cannot put '%s' NIC to promiscuous mode",
					context->config->input->input_source);
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

	//working in a single thread
	if( !IS_SMP_MODE( context )){
		signal( SIGALRM, _alarm_handler );
		//call _alarm_handler 1 second latter
		alarm( 1 );
	}

	//start processing

	//this annotation to let valgrind know that the #pcap_loop() is called before pcap_breakloop()
	EXEC_ONLY_IN_VALGRIND_MODE(ANNOTATE_HAPPENS_BEFORE( &( pcap ) ));
	//this loop is ended when:
	//- then end of pcap file, or,
	//- pcap_breakloop() is called, or,
	//- an error
	//-1: unlimited number of packets to capture.
	ret = pcap_loop( pcap, -1, _got_a_packet, (u_char*) context );

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
			pthread_join( context->smp[i]->pcap->thread_handler, NULL );
		}
	}
	else{
		//cancel any currently active alarm
		alarm( 0 );
		//when there is only one worker running on the main thread
		worker_on_stop( context->smp[0] );
	}


	worker_print_common_statistics( context );

	_print_pcap_stats( context );

	//all workers have been stopped
	_pcap_capture_release( context );
}


