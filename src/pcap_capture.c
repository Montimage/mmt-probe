/*
 * pcap_capture.c
 *
 *  Created on: Mar 29, 2017
 *      Author: montimage
 */

#include <pcap.h>
#include <pthread.h>
#include "mmt_core.h"
#include "processing.h"
#include "lib/packet_hash.h"
#include "lib/data_spsc_ring.h"
#include "lib/optimization.h"
#include "lib/system_info.h"
#include <netinet/tcp.h>
#include <stdlib.h>

#include "lib/security.h"
static int errcode = EXIT_FAILURE;
struct pcap_stat pcs; /* packet capture filter stats */
int got_stats = 0; /* capture stats have been obtained */
int ignored = 0; /* number of packets !decapsulated for stats */

uint64_t nb_packets_dropped_by_mmt = 0;
uint64_t nb_packets_processed_by_mmt = 0;
pcap_t *handle = 0; /* packet capture handle */
int volatile reader_ready = 0; /* reader thread no longer needs root */
int push, stop; /* flags for inter-thread communication */
sec_wrapper_t * security2_single_thread = NULL;

void clean_up_security2(mmt_probe_struct_t * mmt_probe){
	if( mmt_probe->mmt_conf->security2_enable){
		//get number of packets being processed by security
		uint64_t msg_count  = security2_single_thread->msg_count;
		//free security
		size_t alerts_count = unregister_security( security2_single_thread );

		printf ("[mmt-probe-1]{%3d,%9"PRIu64",%9"PRIu64",%7zu}\n",mmt_probe->smp_threads->thread_index, nb_packets_processed_by_mmt, msg_count, alerts_count );
	}
}

#ifdef PCAP
 /*This function initializes/registers different handlers, functions and reports for each thread and
 * provides packet for processing in mmt-dpi.
 **/
void * smp_thread_routine(void *arg) {
	struct timeval tv;
	struct smp_thread *th = (struct smp_thread *) arg;
	char mmt_errbuf[1024];
	char lg_msg[256];
	int  i = 0;
	struct packet_element *pkt;
	uint32_t tail;
	long avail_processors;
	int size;
	sec_wrapper_t * security2 = NULL;

	mmt_probe_context_t * probe_context = get_probe_context_config();

	sprintf(lg_msg, "Starting thread %i", th->thread_index);

	mmt_log(probe_context, MMT_L_INFO, MMT_T_INIT, lg_msg);

	//move this thread to a specific processor
	avail_processors = get_number_of_online_processors();
	if( avail_processors > 1 ){
		avail_processors -= 1;//avoid zero that is using by Reader
		(void) move_the_current_thread_to_a_core( th->thread_index % avail_processors + 1, -10 );
	}
	//printf ("core =%ld, th_id =%u\n",th->thread_number % avail_processors + 1,th->thread_number);

	//Initialize an MMT handler
	pthread_spin_lock(&spin_lock);
	//pthread_mutex_lock(&mutex_lock);
	th->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	//pthread_mutex_unlock(&mutex_lock);
	pthread_spin_unlock(&spin_lock);

	if (!th->mmt_handler) {  /*pcap error ?*/
		sprintf(lg_msg, "Error while starting thread number %i", th->thread_index);
		mmt_log(probe_context, MMT_L_INFO, MMT_T_INIT, lg_msg);
		return &errcode;
	}

	//th->iprobe.data_out = NULL;
	//th->iprobe.radius_out = NULL;
	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		reset_microflows_stats(&th->iprobe.mf_stats[i]);
		th->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
		th->iprobe.mf_stats[i].application_id = i;
	}
	th->iprobe.instance_id = th->thread_index;
	// customized packet and session handling functions are then registered*
	if(probe_context->enable_session_report == 1) {
		register_session_timer_handler(th->mmt_handler, print_ip_session_report, th);
		register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
		flowstruct_init(th); // initialize our event handler
		if (probe_context->condition_based_reporting_enable == 1)conditional_reports_init(th);// initialize our condition reports
		if (probe_context->radius_enable == 1)radius_ext_init(th); // initialize radius extraction and attribute event handler
                atomic_store (&th->session_report_flag, 0);
	}
	set_default_session_timed_out(th->mmt_handler, probe_context->default_session_timeout);
	set_long_session_timed_out(th->mmt_handler, probe_context->long_session_timeout);
	set_short_session_timed_out(th->mmt_handler, probe_context->short_session_timeout);
	set_live_session_timed_out(th->mmt_handler, probe_context->live_session_timeout);

	if (probe_context->event_based_reporting_enable == 1)event_reports_init(th); // initialize our event reports
	if (probe_context->enable_security_report == 0 && probe_context->enable_security_report_multisession == 0)proto_stats_init(th);//initialise this before security_reports_init
	if (probe_context->enable_security_report == 1)security_reports_init(th);
#ifdef HTTP_RECONSTRUCT
	if (probe_context->http_reconstruct_enable == 1) http_reconstruct_init(th);
#endif // End of HTTP_RECONSTRUCT
	if (probe_context->enable_security_report_multisession == 1)security_reports_multisession_init(th);// should be defined before proto_stats_init


	//security2
	if( probe_context->security2_enable ){

		th->security2_lcore_id = (probe_context->thread_nb + 1) + th->thread_index * probe_context->security2_threads_count;

		if ((th->security2_lcore_id + probe_context->security2_threads_count) > get_number_of_online_processors()){

			th->security2_lcore_id = th->thread_index % avail_processors + 1;
		}

		//lcore_id on which security2 will run
		uint32_t *sec_cores_mask = malloc( sizeof( uint32_t ) * probe_context->security2_threads_count );

		int k = 1;
		for( i=0; i < probe_context->security2_threads_count; i++ ){
			if (th->security2_lcore_id + i >= get_number_of_online_processors()){
				th->security2_lcore_id = k++;
				if (k == get_number_of_online_processors()) k = 1;
				sec_cores_mask[ i ] = th->security2_lcore_id;
			}else {
				sec_cores_mask[ i ] = th->security2_lcore_id + i;
			}
		}

		//th->security2_alerts_output_count = 0;
		security2 = register_security( th->mmt_handler,
				probe_context->security2_threads_count,
				sec_cores_mask, probe_context->security2_rules_mask,
				th->thread_index == 0,//false, //true,
				//this callback will be called from one or many different threads (depending on #security2_threads_count)
				//print verdict only if output to file or redis is enable
				( probe_context->output_to_file_enable && probe_context->security2_output_channel[0] )
				|| ( probe_context->redis_enable &&  probe_context->security2_output_channel[1] )
				|| ( probe_context->kafka_enable &&  probe_context->security2_output_channel[2] ) ? security_print_verdict : NULL,th
		);

		free( sec_cores_mask );
	}


	th->nb_packets = 0;
	data_spsc_ring_t *fifo     = &th->fifo;
	mmt_handler_t *mmt_handler = th->mmt_handler;

	while (likely (!do_abort)) {

		if(time(NULL)- th->last_stat_report_time >= probe_context->stats_reporting_period ||
				th->pcap_current_packet_time - th->pcap_last_stat_report_time >= probe_context->stats_reporting_period){
			th->report_counter++;
			th->last_stat_report_time = time(NULL);
			th->pcap_last_stat_report_time = th->pcap_current_packet_time;
			//if (probe_context->enable_session_report == 1)process_session_timer_handler(th->mmt_handler);
		//	if (probe_context->enable_proto_without_session_stats == 1 || probe_context->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, th);
                        
			    if (atomic_load (&th->config_updated) == 1){
                                if (atomic_load (&th->event_report_flag) == 1) event_reports_init ((void *) th); //if event report is changed then register
                                if (atomic_load (&th->condition_report_flag) == 1)conditional_reports_init(th);// initialize our condition reports

                                if (atomic_load (&th->session_report_flag) == 1 && probe_context->enable_session_report == 1){ 
                                    register_session_timer_handler(th->mmt_handler, print_ip_session_report, th);
                                    register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
                                    flowstruct_uninit(th);
                                    flowstruct_init(th); // initialize our event handler
                                    if (probe_context->condition_based_reporting_enable == 1)conditional_reports_init(th);// initialize our condition reports
                                    if (probe_context->radius_enable == 1)radius_ext_init(th); // initialize radius extraction and attribute event handler
                                    printf ("thread_id_smp = %u \n",th->thread_index);
                                   atomic_store (&th->session_report_flag, 0); 
                               }else {
                                    flowstruct_uninit(th);
                                    atomic_store (&th->session_report_flag, 0);
                               }

                            atomic_store(&th->config_updated, 0); // update implemented in each thread
                      }
                      if (probe_context->enable_session_report == 1 )process_session_timer_handler(th->mmt_handler);
                      if (probe_context->enable_proto_without_session_stats == 1 || probe_context->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, th);
	
	        }

		//get number of packets being available
		size = data_spsc_ring_pop_bulk( fifo, &tail );
		/* if no packet has arrived sleep 1 milli-second */
		if ( size <= 0 ) {
			tv.tv_sec = 0;
			tv.tv_usec = 1000;
			//fprintf(stdout, "No more packets for thread %i --- waiting\n", th->thread_number);
			select(0, NULL, NULL, NULL, &tv);
			//nanosleep( (const struct timespec[]){{0, 1000000L}}, NULL );
		} else {  /* else remove number of packets from list and process it */

			//the last packet will be verified after (not in for)
			size --;
			for( i=0; i<size; i++ ){
				pkt = (struct packet_element *) data_spsc_ring_get_data( fifo, i + tail);
				packet_process( mmt_handler, &pkt->header, pkt->data );
			}
			th->nb_packets += size;

			//only the last packet in the queue may has NULL data
			pkt = (struct packet_element *) data_spsc_ring_get_data( fifo, size + tail);

			/* is it a dummy packet ? => means thread must exit */
			if( unlikely( pkt->data == NULL ))
				break;
			else{
				packet_process( mmt_handler, &pkt->header, pkt->data );
				th->nb_packets ++;
                                printf ("th_nb = %u, packet_id =%lu\n",th->thread_index, th->nb_packets);
			}

			//update new position of ring's tail
			data_spsc_ring_update_tail( fifo, tail, size + 1); //+1 as size-- above
		}
	} //end while(1)

	//printf("thread %d : %"PRIu64" \n", th->thread_index, th->nb_packets );

	if(th->mmt_handler != NULL){
		if( probe_context->security2_enable ){
			//get number of packets being processed by security
			uint64_t msg_count  = security2->msg_count;
			//free security
			size_t alerts_count = unregister_security( security2 );

			printf ("[mmt-probe-1]{%3d,%9"PRIu64",%9"PRIu64",%7zu}\n",th->thread_index, th->nb_packets, msg_count, alerts_count );
		}else
			printf ("[mmt-probe-1]{%3d,%9"PRIu64"}\n",th->thread_index, th->nb_packets );

		radius_ext_cleanup(th->mmt_handler); // cleanup our event handler for RADIUS initializations
		flowstruct_cleanup(th->mmt_handler); // cleanup our event handler
		th->report_counter++;
		if (probe_context->enable_proto_without_session_stats == 1 || probe_context->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, th);
		//process_session_timer_handler(th->mmt_handler);
		if (cleanup_registered_handlers (th) == 0){
			fprintf(stderr, "Error while unregistering attribute  handlers thread_nb = %u !\n",th->thread_index);
		}

		mmt_close_handler(th->mmt_handler);
		th->mmt_handler = NULL;
	}

	sprintf(lg_msg, "Thread %i ended (%"PRIu64" packets)", th->thread_index, th->nb_packets);
	//printf("Thread %i ended (%"PRIu64" packets)\n", th->thread_number, nb_pkts);
	mmt_log(probe_context, MMT_L_INFO, MMT_T_END, lg_msg);
	//fprintf(stdout, "Thread %i ended (%u packets)\n", th->thread_number, nb_pkts);
	return NULL;
}

struct dispatcher_struct {
	char * filename;
	pthread_t handle;
	int nb;
};

/* This function reads the packets from trace file and process them.
 *  In case of multi-thread, it reads the packets from the trace file and
 *  dispatch it to one of the thread queues.
 */
void process_trace_file(char * filename, mmt_probe_struct_t * mmt_probe) {
	int i;
	struct dispatcher_struct dispatcher[2];

	uint64_t packets_count = 0;
	pcap_t *pcap;
	const u_char *data;
	struct pkthdr header;
	struct pcap_pkthdr pkthdr;
	char errbuf[1024];
	char lg_msg[1024];
	struct smp_thread *th;
	static uint32_t p_hash = 0;
	static struct packet_element *pkt;
	static void *pdata;
	long avail_processors;

	avail_processors = get_number_of_online_processors();
	(void) move_the_current_thread_to_a_core( 0, -10 );

	//Initialise MMT_Security
	if(mmt_probe->mmt_conf->security_enable == 1)
		init_mmt_security(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->properties_file,(void *)mmt_probe->smp_threads );
	//End initialise MMT_Security


	//Call mmt_core function that will parse the packet and analyse it.


	if (mmt_probe->mmt_conf->thread_nb == 1) {

		//security2

		if( mmt_probe->mmt_conf->security2_enable ){
			mmt_probe->smp_threads->security2_lcore_id = (mmt_probe->mmt_conf->thread_nb) + mmt_probe->smp_threads->thread_index * mmt_probe->mmt_conf->security2_threads_count;

			if ((mmt_probe->smp_threads->security2_lcore_id + mmt_probe->mmt_conf->security2_threads_count) > get_number_of_online_processors()){
				mmt_probe->smp_threads->security2_lcore_id = mmt_probe->smp_threads->thread_index % avail_processors + 1;
			}

			//lcore_id on which security2 will run
			uint32_t *sec_cores_mask = malloc( sizeof( uint32_t ) * mmt_probe->mmt_conf->security2_threads_count );
			int k = 1;
			for( i=0; i < mmt_probe->mmt_conf->security2_threads_count; i++ ){
				if (mmt_probe->smp_threads->security2_lcore_id + i >= get_number_of_online_processors()){
					mmt_probe->smp_threads->security2_lcore_id = k++;
					if (k == get_number_of_online_processors()) k = 1;
					sec_cores_mask[ i ] = mmt_probe->smp_threads->security2_lcore_id;
				}else {
					sec_cores_mask[ i ] = mmt_probe->smp_threads->security2_lcore_id + i;
				}
			}

			//mmt_probe->smp_threads->security2_alerts_output_count = 0;
			security2_single_thread = register_security( mmt_probe->smp_threads->mmt_handler,
					mmt_probe->mmt_conf->security2_threads_count,
					sec_cores_mask, mmt_probe->mmt_conf->security2_rules_mask,
					mmt_probe->smp_threads->thread_index == 0,//false, //true,
					//this callback will be called from one or many different threads (depending on #security2_threads_count)
					//print verdict only if output to file or redis is enable
					( mmt_probe->mmt_conf->output_to_file_enable && mmt_probe->mmt_conf->security2_output_channel[0] )
					|| ( mmt_probe->mmt_conf->redis_enable &&  mmt_probe->mmt_conf->security2_output_channel[1] )
					|| ( mmt_probe->mmt_conf->kafka_enable &&  mmt_probe->mmt_conf->security2_output_channel[2] ) ? security_print_verdict : NULL,
							mmt_probe->smp_threads );

			free( sec_cores_mask );
		}

		//security2

		pcap = pcap_open_offline(filename, errbuf); // open offline trace

		if (!pcap) {  /*pcap error ?*/
			sprintf(lg_msg, "Error while opening pcap file: %s --- error msg: %s", filename, errbuf);
			printf("Error: Verify the name and the location of the trace file to be analysed \n ");
			mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_P_TRACE_ERROR, lg_msg);
			return;
		}
		sprintf(lg_msg, "Start processing trace file: %s", filename);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_START_PROCESS_TRACE, lg_msg);
		//One thread for reading packets and processing them
		while ((data = pcap_next(pcap, &pkthdr))) {
			header.ts = pkthdr.ts;
			header.caplen = pkthdr.caplen;
			header.len = pkthdr.len;
			header.user_args = NULL;
                        printf("output to file = %u\n",mmt_probe->mmt_conf->output_to_file_enable);
			if(time(NULL)- mmt_probe->smp_threads->last_stat_report_time >= mmt_probe->mmt_conf->stats_reporting_period ||
					mmt_probe->smp_threads->pcap_current_packet_time - mmt_probe->smp_threads->pcap_last_stat_report_time >= mmt_probe->mmt_conf->stats_reporting_period){
				mmt_probe->smp_threads->report_counter++;
				mmt_probe->smp_threads->last_stat_report_time = time(NULL);
				mmt_probe->smp_threads->pcap_last_stat_report_time = mmt_probe->smp_threads->pcap_current_packet_time;
				if (mmt_probe->mmt_conf->enable_session_report == 1)process_session_timer_handler(mmt_probe->smp_threads->mmt_handler);
				if (mmt_probe->mmt_conf->enable_proto_without_session_stats == 1 || mmt_probe->mmt_conf->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, (void *)mmt_probe->smp_threads);
			}


			if (!packet_process(mmt_probe->smp_threads->mmt_handler, &header, data)) {
				sprintf(lg_msg, "MMT Extraction failure! Error while processing packet number %"PRIu64"", packets_count);
				mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_E_PROCESS_ERROR, lg_msg);
			}
			//packets_count++;
			nb_packets_processed_by_mmt ++;
		}
		pcap_close(pcap);

		sprintf(lg_msg, "End processing trace file: %s", filename);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_END_PROCESS_TRACE, lg_msg);
	}else {//We have more than one thread for processing packets! dispatch the packet to one of them
		pcap = pcap_open_offline(filename, errbuf); // open offline trace

		if (!pcap) { /* pcap error ?*/
			sprintf(lg_msg, "Error while opening pcap file: %s --- error msg: %s", filename, errbuf);
			printf("Error: Verify the name and the location of the trace file to be analysed \n ");
			mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_P_TRACE_ERROR, lg_msg);
			return;
		}

		sprintf(lg_msg, "Start processing trace file: %s", filename);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_START_PROCESS_TRACE, lg_msg);
		int is_queue_full = 0;
		while (1) {

			//if( ! is_queue_full )
			data = pcap_next(pcap, &pkthdr);
			if( ! data ){
				//printf("break read pcap");
				fflush( stdout );
				for( i = 0; i < mmt_probe->mmt_conf->thread_nb; i++){
					th = &mmt_probe->smp_threads[i];
					if( data_spsc_ring_get_tmp_element( &th->fifo, &pdata ) != QUEUE_SUCCESS)
						continue;

					pkt = (struct packet_element *) pdata;
					/* fill smp_pkt fields and copy packet data from pcap buffer*/
					pkt->header.len    = pkthdr.len;
					pkt->header.caplen = pkthdr.caplen;
					pkt->header.ts     = pkthdr.ts;
					pkt->data          = NULL; //put data in the same memory segment but after sizeof( pkt )
					data_spsc_ring_push_tmp_element( &th->fifo );
				}

				//printf("I lost %"PRIu64" but I processed %"PRIu64"", nb_packets_dropped_by_mmt, nb_packets_processed_by_mmt);
				break;
			}
			p_hash = get_packet_hash_number(data, pkthdr.caplen) % (mmt_probe->mmt_conf->thread_nb );
			th     = &mmt_probe->smp_threads[ p_hash ];

			data_spsc_ring_get_tmp_element( &th->fifo, &pdata );

			pkt = (struct packet_element *) pdata;
			/* fill smp_pkt fields and copy packet data from pcap buffer*/
			pkt->header.len    = pkthdr.len;
			pkt->header.caplen = pkthdr.caplen;
			pkt->header.ts     = pkthdr.ts;
			pkt->data          = (u_char *)( &pkt[ 1 ]); //put data in the same memory segment but after sizeof( pkt )
			memcpy(pkt->data, data, pkthdr.caplen);
			while (  data_spsc_ring_push_tmp_element( &th->fifo ) != QUEUE_SUCCESS ){
				usleep(10);
				//nb_packets_dropped_by_mmt ++;
				//th->nb_dropped_packets ++;

			}
		}
		pcap_close(pcap);
	}
}

//online-single thread
/* This function processes the packet in online single thread mode.
 * */
void got_packet_single_thread(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	struct smp_thread *th;
	struct pkthdr header;
	static uint32_t p_hash = 0;
	static void *pdata;
	static struct packet_element *pkt;

	struct mmt_probe_struct  * mmt_probe = (struct mmt_probe_struct  *) args;
	header.ts = pkthdr->ts;
	header.caplen = pkthdr->caplen;
	header.len = pkthdr->len;
	header.user_args = NULL;
        //printf("output to file = %u\n",mmt_probe->mmt_conf->output_to_file_enable);
	if(time(NULL)- mmt_probe->smp_threads->last_stat_report_time >= mmt_probe->mmt_conf->stats_reporting_period){
                if (atomic_load (config_updated) == 1){
                   if (atomic_load (event_report_flag) == 1) event_reports_init ((void *) mmt_probe->smp_threads);
                   if (atomic_load (condition_report_flag) == 1)conditional_reports_init((void *) mmt_probe->smp_threads);// initialize our condition reports

                   if (atomic_load (session_report_flag) == 1 && mmt_probe->mmt_conf->enable_session_report == 1){
                       register_session_timer_handler(mmt_probe->smp_threads->mmt_handler, print_ip_session_report, (void *) mmt_probe->smp_threads);
                       register_session_timeout_handler(mmt_probe->smp_threads->mmt_handler, classification_expiry_session, (void *) mmt_probe->smp_threads);
                       flowstruct_uninit((void *)mmt_probe->smp_threads); // initialize our event handler

                       flowstruct_init((void *)mmt_probe->smp_threads); // initialize our event handler
                       if(mmt_probe->mmt_conf->condition_based_reporting_enable == 1)conditional_reports_init((void *)mmt_probe->smp_threads);// initialize our conditional reports
                       if(mmt_probe->mmt_conf->radius_enable == 1)radius_ext_init((void *)mmt_probe->smp_threads); // initialize radius extraction and attribute event handler

                       atomic_store(session_report_flag, 0);
                   }else{
                       flowstruct_uninit((void *)mmt_probe->smp_threads); // initialize our event handler
                       atomic_store(session_report_flag, 0);

                   }

                   atomic_store(config_updated, 0);
               }
		mmt_probe->smp_threads->report_counter++;
		mmt_probe->smp_threads->last_stat_report_time = time(NULL);
		if (mmt_probe->mmt_conf->enable_session_report == 1)process_session_timer_handler(mmt_probe->smp_threads->mmt_handler);
		if (mmt_probe->mmt_conf->enable_proto_without_session_stats == 1 || mmt_probe->mmt_conf->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, (void *)mmt_probe->smp_threads);
	}

	if (!packet_process(mmt_probe->smp_threads->mmt_handler, &header, data)) {
		fprintf(stderr, "MMT Extraction failure! Error while processing packet number %"PRIu64"\n", nb_packets_processed_by_mmt);
		nb_packets_dropped_by_mmt ++;
	}

	nb_packets_processed_by_mmt ++;
	printf("nb_packet_processed = %lu\n ",nb_packets_processed_by_mmt);
}

/* This function is for online multi-thread mode.
 * It  dispatches the packet to one of the thread queues for processing.
 * */
void got_packet_multi_thread(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	struct smp_thread *th;
	uint32_t p_hash = 0;
	void *pdata;
	struct packet_element *pkt;
	struct mmt_probe_struct  * mmt_probe = (struct mmt_probe_struct  *) args;

	p_hash = get_packet_hash_number(data, pkthdr->caplen) % ( mmt_probe->mmt_conf->thread_nb );

	//p_hash = rand() %  (mmt_probe.mmt_conf->thread_nb );
	th     = &mmt_probe->smp_threads[ p_hash ];

	data_spsc_ring_get_tmp_element( &th->fifo, &pdata );

	pkt = (struct packet_element *) pdata;
	/* fill smp_pkt fields and copy packet data from pcap buffer */
	pkt->header.len    = pkthdr->len;
	pkt->header.caplen = pkthdr->caplen;
	pkt->header.ts     = pkthdr->ts;
	pkt->data          = (u_char *)( &pkt[ 1 ]); //put data in the same memory segment but after sizeof( pkt )
	memcpy(pkt->data, data, pkthdr->caplen);

	if(  unlikely( data_spsc_ring_push_tmp_element( &th->fifo ) != QUEUE_SUCCESS ))
	{
		//queue is full
		nb_packets_dropped_by_mmt ++;
		th->nb_dropped_packets ++;
	}
}

/*
 * This function reads stdin or the network and appends to the ring buffer
 */
void *Reader(void *arg) {
	struct mmt_probe_struct * mmt_probe = (struct mmt_probe_struct *) arg;

	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	struct bpf_program fp; /* compiled filter program */
	bpf_u_int32 mask; /* subnet mask */
	bpf_u_int32 net; /* ip */
	int num_packets = -1; /* number of packets to capture */
	//int num_packets = 1000000; /* number of packets to capture */
	int i = 0;

	long avail_processors;

	avail_processors = get_number_of_online_processors();

	(void) move_the_current_thread_to_a_core(0, -15);

	/*
	 * get network number and mask associated with capture device
	 * (needed to compile a bpf expression).
	 */
	if (pcap_lookupnet(mmt_probe->mmt_conf->input_source, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for dev %s: %s\n", mmt_probe->mmt_conf->input_source, errbuf);
		net = 0;
		mask = 0;
	}

	//HUU TODO: need to fix MMT_Security using multithreads
	//Initialise MMT_Security
	//init_sec_lib (mmt_probe->mmt_handler, mmt_probe->mmt_conf->properties_file, OPTION_SATISFIED, OPTION_NOT_SATISFIED, todo_when_property_is_satisfied_or_not,
	//              db_todo_at_start, db_todo_when_property_is_satisfied_or_not);
	//End initialise MMT_Security

	/* open capture device */
	handle = pcap_create(mmt_probe->mmt_conf->input_source, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s\n", errbuf);
		exit(0);
	}
	pcap_set_snaplen(handle, mmt_probe->mmt_conf->requested_snap_len);
	pcap_set_promisc(handle, 1);
	pcap_set_timeout(handle, 0);
	pcap_set_buffer_size(handle, 500*1000*1000);
	pcap_activate(handle);

	reader_ready = 1;

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet. (be sure that you are running probe with root permission)\n", mmt_probe->mmt_conf->input_source);
		exit(0);
	}

	/* compile the filter expression */
	//if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
	//	fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
	//	exit(EXIT_FAILURE);
	//}

	/* apply the compiled filter */
	//if (pcap_setfilter(handle, &fp) == -1) {
	//	fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
	//	exit(EXIT_FAILURE);
	//}
	//Initialise MMT_Security
	if(mmt_probe->mmt_conf->security_enable == 1)
		init_mmt_security( mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->properties_file, (void *)mmt_probe->smp_threads );
	//End initialise MMT_Security

	//security2
	if( mmt_probe->mmt_conf->security2_enable && mmt_probe->mmt_conf->thread_nb == 1 ){
		mmt_probe->smp_threads->security2_lcore_id = (mmt_probe->mmt_conf->thread_nb) + mmt_probe->smp_threads->thread_index * mmt_probe->mmt_conf->security2_threads_count;

		if ((mmt_probe->smp_threads->security2_lcore_id + mmt_probe->mmt_conf->security2_threads_count) > get_number_of_online_processors()){
			mmt_probe->smp_threads->security2_lcore_id = mmt_probe->smp_threads->thread_index % avail_processors + 1;
		}

		//lcore_id on which security2 will run
		uint32_t *sec_cores_mask = malloc( sizeof( uint32_t ) * mmt_probe->mmt_conf->security2_threads_count );
		int k = 1;
		for( i=0; i < mmt_probe->mmt_conf->security2_threads_count; i++ ){
			if (mmt_probe->smp_threads->security2_lcore_id + i >= get_number_of_online_processors()){
				mmt_probe->smp_threads->security2_lcore_id = k++;
				if (k == get_number_of_online_processors()) k = 1;
				sec_cores_mask[ i ] = mmt_probe->smp_threads->security2_lcore_id;
			}else {
				sec_cores_mask[ i ] = mmt_probe->smp_threads->security2_lcore_id + i;
			}
		}

		//mmt_probe->smp_threads->security2_alerts_output_count = 0;
		security2_single_thread = register_security( mmt_probe->smp_threads->mmt_handler,
				mmt_probe->mmt_conf->security2_threads_count,
				sec_cores_mask, mmt_probe->mmt_conf->security2_rules_mask,
				mmt_probe->smp_threads->thread_index == 0,//false, //true,
				//this callback will be called from one or many different threads (depending on #security2_threads_count)
				//print verdict only if output to file or redis or kafka is enable
				( mmt_probe->mmt_conf->output_to_file_enable && mmt_probe->mmt_conf->security2_output_channel[0] )
				|| ( mmt_probe->mmt_conf->redis_enable &&  mmt_probe->mmt_conf->security2_output_channel[1] )
				|| ( mmt_probe->mmt_conf->kafka_enable &&  mmt_probe->mmt_conf->security2_output_channel[2] ) ? security_print_verdict : NULL,
						mmt_probe->smp_threads );

		free( sec_cores_mask );
	}
	//security2




	/* now we can set our callback function */
	if (mmt_probe->mmt_conf->thread_nb > 1){
		pcap_loop(handle, num_packets, got_packet_multi_thread, (void *) mmt_probe);
	}else {
		while (1){
			pcap_dispatch(handle, num_packets, got_packet_single_thread,(void *) mmt_probe);
			if(time(NULL)- mmt_probe->smp_threads->last_stat_report_time  >= mmt_probe->mmt_conf->stats_reporting_period){
				mmt_probe->smp_threads->report_counter ++;
				mmt_probe->smp_threads->last_stat_report_time = time(NULL);
				if(mmt_probe->mmt_conf->enable_session_report == 1)process_session_timer_handler(mmt_probe->smp_threads->mmt_handler);
				if (mmt_probe->mmt_conf->enable_proto_without_session_stats == 1 || mmt_probe->mmt_conf->enable_IP_fragmentation_report == 1)iterate_through_protocols(protocols_stats_iterator, (void *)mmt_probe->smp_threads);
			}

		}
	}

	//fprintf(stderr, "\n%d packets captured\n", captured);

	/* cleanup */
	pcap_freecode(&fp);
#ifndef RHEL3
	pcap_close(handle);
#endif /* RHEL3 */
	stop = 1;
	fflush(stderr);
	pthread_exit(NULL);
}

void process_interface(char * ifname, struct mmt_probe_struct * mmt_probe) {
	Reader((void*) mmt_probe );
	return;

}
//BW: TODO: add the pcap handler to the mmt_probe (or internal structure accessible from it) in order to be able to close it here
void cleanup(int signo, mmt_probe_struct_t * mmt_probe) {
	mmt_probe_context_t * mmt_conf = mmt_probe->mmt_conf;
	int i;
	if (handle != NULL){
		pcap_breakloop(handle);
		stop = 1;
		if (got_stats) return;

		if (pcap_stats(handle, &pcs) < 0) {
			(void) fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(handle));
		} else got_stats = 1;

		if (ignored > 0) {
			fprintf(stderr, "%d packets ignored (too small to decapsulate)\n", ignored);
		}
		if (got_stats) {
			(void) fprintf(stderr, "\n%12d packets received by filter\n", pcs.ps_recv);
			(void) fprintf(stderr, "%12d packets dropped by NIC (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
			(void) fprintf(stderr, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
			(void) fprintf(stderr, "%12"PRIu64" packets dropped by MMT (%3.2f%%) \n", nb_packets_dropped_by_mmt, nb_packets_dropped_by_mmt * 100.0 /  pcs.ps_recv );
			fflush(stderr);
		}
		if( mmt_conf->thread_nb == 1)
			(void) fprintf(stderr, "%12"PRIu64" packets processed by MMT (%3.2f%%) \n", nb_packets_processed_by_mmt, nb_packets_processed_by_mmt * 100.0 /  pcs.ps_recv );
		else
			for (i = 0; i < mmt_conf->thread_nb; i++)
				(void) fprintf( stderr, "- thread %2d processed %12"PRIu64" packets, dropped %12"PRIu64"\n",
						mmt_probe->smp_threads[i].thread_index, mmt_probe->smp_threads[i].nb_packets, mmt_probe->smp_threads[i].nb_dropped_packets );
		fflush(stderr);
#ifdef RHEL3
		pcap_close(handle);
#endif /* RHEL3 */
	}
}

int pcap_capture(struct mmt_probe_struct * mmt_probe){
	int i = 0, j = 0;
	char mmt_errbuf[1024];
	char lg_msg[1024];

	//For MMT_Security
	if (mmt_probe->mmt_conf->security_enable == 1)
		todo_at_start(mmt_probe->mmt_conf->dir_out);
	//End for MMT_Security
	mmt_probe->mmt_conf->file_modified_time = time (0);
	//Initialization

	if (mmt_probe->mmt_conf->thread_nb == 1) {
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_E_INIT, "Initializating MMT Extraction engine! Single threaded operation.");
		mmt_probe->smp_threads = (struct smp_thread *) calloc(mmt_probe->mmt_conf->thread_nb,sizeof (struct smp_thread));
		mmt_probe->smp_threads->last_stat_report_time = time(0);
		mmt_probe->smp_threads->pcap_last_stat_report_time = 0;
		mmt_probe->smp_threads->pcap_current_packet_time = 0;
#ifdef HTTP_RECONSTRUCT
		mmt_probe->smp_threads->list_http_session_data = NULL;
#endif		
		//One thread for reading packets and processing them
		//Initialize an MMT handler
		mmt_probe->smp_threads->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);

		if (!mmt_probe->smp_threads->mmt_handler) { /* pcap error ? */
			fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
			mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_E_INIT_ERROR, "MMT Extraction handler initialization error! Exiting!");
			return EXIT_FAILURE;
		}


//    while (mmt_probe->mmt_conf->event_reports != NULL){
  //      printf ("enable___pcap...................\n");
    //    mmt_probe->mmt_conf->event_reports = mmt_probe->mmt_conf->event_reports->next;
    //}





		//mmt_probe->iprobe.instance_id = 0;
		mmt_probe->smp_threads->thread_index = 0;
		for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
			reset_microflows_stats(&mmt_probe->smp_threads->iprobe.mf_stats[i]);
			mmt_probe->smp_threads->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
			mmt_probe->smp_threads->iprobe.mf_stats[i].application_id = i;
		}
		mmt_probe->smp_threads->iprobe.instance_id = mmt_probe->smp_threads->thread_index;
		mmt_probe->smp_threads->thread_index = 0;

		pthread_spin_init(&mmt_probe->smp_threads->lock, 0);

		// customized packet and session handling functions are then registered
		if(mmt_probe->mmt_conf->enable_session_report == 1) {
			register_session_timer_handler(mmt_probe->smp_threads->mmt_handler, print_ip_session_report, (void *) mmt_probe->smp_threads);
			register_session_timeout_handler(mmt_probe->smp_threads->mmt_handler, classification_expiry_session, (void *) mmt_probe->smp_threads);
			flowstruct_init((void *)mmt_probe->smp_threads); // initialize our event handler
			if(mmt_probe->mmt_conf->condition_based_reporting_enable == 1)conditional_reports_init((void *)mmt_probe->smp_threads);// initialize our conditional reports
			if(mmt_probe->mmt_conf->radius_enable == 1)radius_ext_init((void *)mmt_probe->smp_threads); // initialize radius extraction and attribute event handler
                        atomic_store (session_report_flag, 0);
		}
		set_default_session_timed_out(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->default_session_timeout);
		set_long_session_timed_out(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->long_session_timeout);
		set_short_session_timed_out(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->short_session_timeout);
		set_live_session_timed_out(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->live_session_timeout);

		if(mmt_probe->mmt_conf->event_based_reporting_enable == 1)event_reports_init((void *)mmt_probe->smp_threads); // initialize our event reports
		if (mmt_probe->mmt_conf->enable_security_report == 1)security_reports_init((void *)mmt_probe->smp_threads);// should be defined before proto_stats_init
		if (mmt_probe->mmt_conf->enable_security_report == 0)proto_stats_init(mmt_probe->smp_threads);
#ifdef HTTP_RECONSTRUCT
		if (mmt_probe->mmt_conf->http_reconstruct_enable == 1) http_reconstruct_init(mmt_probe->smp_threads);
#endif // End of HTTP_RECONSTRUCT
		if (mmt_probe->mmt_conf->enable_security_report_multisession == 1)security_reports_multisession_init((void *)mmt_probe->smp_threads);// should be defined before proto_stats_init
		if (mmt_probe->mmt_conf->enable_security_report == 0 && mmt_probe->mmt_conf->enable_security_report_multisession == 0 )proto_stats_init(mmt_probe->smp_threads);
		//initialisation of multisession report

		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_E_STARTED, "MMT Extraction engine! successfully initialized in a single threaded operation.");
                atomic_store (config_updated, 0);
	} else {
		//Multiple threads for processing the packets
		/*
		 * Array of list of packets for all threads
		 */
		sprintf(lg_msg, "Initializating MMT Extraction engine! Multi threaded operation (%i threads)", mmt_probe->mmt_conf->thread_nb);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_E_INIT, lg_msg);
		mmt_probe->smp_threads = (struct smp_thread *) calloc(mmt_probe->mmt_conf->thread_nb, sizeof (struct smp_thread));
		/* run threads */
		for (i = 0; i < mmt_probe->mmt_conf->thread_nb; i++) {
			init_list_head((struct list_entry *) &mmt_probe->smp_threads[i].pkt_head);
			pthread_spin_init(&mmt_probe->smp_threads[i].lock, 0);
			mmt_probe->smp_threads[i].last_stat_report_time = time(0);
			mmt_probe->smp_threads[i].pcap_last_stat_report_time = 0;
			mmt_probe->smp_threads[i].pcap_current_packet_time = 0;
			//mmt_probe->smp_threads[i].last_msg_report_time = time(0);
			mmt_probe->smp_threads[i].null_pkt.pkt.data = NULL;

			mmt_probe->smp_threads[i].nb_dropped_packets = 0;
			mmt_probe->smp_threads[i].nb_packets         = 0;

			mmt_probe->smp_threads[i].thread_index = i;
#ifdef HTTP_RECONSTRUCT
			mmt_probe->smp_threads[i].list_http_session_data = NULL;
#endif			
			if( data_spsc_ring_init( &mmt_probe->smp_threads[i].fifo, mmt_probe->mmt_conf->thread_queue_plen, mmt_probe->mmt_conf->requested_snap_len ) != 0 ){
				perror("Not enough memory. Please reduce thread-queue or thread-nb in .conf");
				//free memory allocated
				for(j = 0; j <= i; j++)
					data_spsc_ring_free( &mmt_probe->smp_threads[j].fifo );
				exit( 0 );
			}

			pthread_create(&mmt_probe->smp_threads[i].handle, NULL,
					smp_thread_routine, &mmt_probe->smp_threads[i]);

		}

		sprintf(lg_msg, "MMT Extraction engine! successfully initialized in a multi threaded operation (%i threads)", mmt_probe->mmt_conf->thread_nb);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_E_STARTED, lg_msg);
	}
	//we need to enable timer both for file and redis output since we need report number 200 (to check that probe is alive)
	//TODO: Sementation faults
	start_timer( mmt_probe->mmt_conf->sampled_report_period, flush_messages_to_file_thread, (void *) mmt_probe);

	//Offline or Online processing

	if (mmt_probe->mmt_conf->input_mode == OFFLINE_ANALYSIS) {
                		process_trace_file(mmt_probe->mmt_conf->input_source, mmt_probe); //Process single offline trace
		//We don't close the files here because they will be used when the handler is closed to report still to timeout flows
	}else if (mmt_probe->mmt_conf->input_mode == ONLINE_ANALYSIS) {
		process_interface(mmt_probe->mmt_conf->input_source, mmt_probe); //Process single offline trace
		//We don't close the files here because they will be used when the handler is closed to report still to timeout flows
	}
	return 0;
}
#endif


