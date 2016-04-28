/*
 * File:   main.c

gcc -gdwarf-2 -o probe src/smp_main.c  src/processing.c src/web_session_report.c src/thredis.c \
src/send_msg_to_file.c src/send_msg_to_redis.c src/ip_statics.c src/rtp_session_report.c src/ftp_session_report.c \
src/event_based_reporting.c src/protocols_report.c src/ssl_session_report.c src/default_app_session_report.c \
src/microflows_session_report.c src/radius_reporting.c src/security_analysis.c src/parseoptions.c src/license.c \
-lmmt_core -lmmt_tcpip -lmmt_security -lxml2 -ldl -lpcap -lconfuse -lhiredis -lpthread


 * Author: montimage
 *
 * Created on 31 mai 2011, 14:09
 */


//TODO:
//Debug MMT_Security for multi-threads


#define _GNU_SOURCE
#ifdef linux
#include <syscall.h>
#endif
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h> //usleep, sleep
#include "mmt_core.h"
#include "processing.h"

#include "lib/packet_hash.h"
#include "lib/data_spsc_ring.h"
#include "lib/optimization.h"
#include "lib/system_info.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>



#define DLT_EN10MB 1    /* Ethernet (10Mb) */
#define READ_PRIO	-15	/* niceness value for Reader thread */
#define SNAP_LEN 65535	/* apparently what tcpdump uses for -s 0 */
#define READER_CPU	0	/* assign Reader thread to this CPU */
#define MAX_FILE_NAME 500
static int okcode  = EXIT_SUCCESS;
static int errcode = EXIT_FAILURE;




pcap_t *handle = 0; /* packet capture handle */
struct pcap_stat pcs; /* packet capture filter stats */
int got_stats = 0; /* capture stats have been obtained */
int push, stop; /* flags for inter-thread communication */
int d_snap_len = SNAP_LEN; /* actual limit on packet capture size */
int snap_len = SNAP_LEN; /* requested limit on packet capture size */
int volatile reader_ready = 0; /* reader thread no longer needs root */
char *filter_exp = ""; /* decapsulation filter expression */
int captured = 0; /* number of packets captured for stats */
int ignored = 0; /* number of packets !decapsulated for stats */

uint64_t nb_packets_dropped_by_mmt = 0;
uint64_t nb_packets_processed_by_mmt = 0;

static void terminate_probe_processing(int wait_thread_terminate);


uint32_t get_2_power(uint32_t nb) {
	uint32_t ret = -1;
	while (nb != 0) {
		nb >>= 1;
		ret++;
	}
	return ret;
}

static void *smp_thread_routine(void *arg) {
	struct timeval tv;
	struct smp_thread *th = (struct smp_thread *) arg;
	char mmt_errbuf[1024];
	char lg_msg[256];
	int  i = 0;
	struct packet_element *pkt;
	void *pdata;
	long avail_processors;
	
	sprintf(lg_msg, "Starting thread %i", th->thread_number);

	mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_T_INIT, lg_msg);

	//move this thread to a specific processor
	avail_processors = get_number_of_online_processors();
	if( avail_processors > 0 ){
		avail_processors -= 1;//avoid zero that is using by Reader
		(void) move_the_current_thread_to_a_core( th->thread_number % avail_processors + 1, 0 );
	}

	//Initialize an MMT handler
	pthread_spin_lock(&spin_lock);
	//pthread_mutex_lock(&mutex_lock);
	th->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
	//pthread_mutex_unlock(&mutex_lock);
	pthread_spin_unlock(&spin_lock);

	if (!th->mmt_handler) { /* pcap error ? */
		sprintf(lg_msg, "Error while starting thread number %i", th->thread_number);
		mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_T_INIT, lg_msg);
		return &errcode;
	}

	//th->iprobe.data_out = NULL;
	//th->iprobe.radius_out = NULL;
	for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
		reset_microflows_stats(&th->iprobe.mf_stats[i]);
		th->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
		th->iprobe.mf_stats[i].application_id = i;
	}
	th->iprobe.instance_id = th->thread_number;
	// customized packet and session handling functions are then registered

	if(mmt_probe.mmt_conf->enable_flow_stats) {
		register_session_timer_handler(th->mmt_handler,print_ip_session_report,th);
		register_session_timeout_handler(th->mmt_handler, classification_expiry_session, th);
		flowstruct_init(th); // initialize our event handler
		if(mmt_probe.mmt_conf->event_based_reporting_enable==1)event_reports_init(th); // initialize our event reports
		conditional_reports_init(th->mmt_handler);// initialize our condition reports
		if(mmt_probe.mmt_conf->radius_enable==1)radius_ext_init(th); // initialize radius extraction and attribute event handler
	}


	proto_stats_init(th->mmt_handler);
	th->nb_packets = 0;
	mmt_probe_context_t * probe_context = get_probe_context_config();
	char message[MAX_MESS + 1];

	while ( 1 ) {

		if(time(NULL)- th->last_stat_report_time >= mmt_probe.mmt_conf->stats_reporting_period){
			th->last_stat_report_time=time(NULL);
			process_session_timer_handler(th->mmt_handler);
			if (probe_context->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, th);
		}
		//if(time(NULL)- th->last_msg_report_time >= mmt_probe.mmt_conf->sampled_report_period){
		//	th->last_msg_report_time = time(NULL);
		//}

		/* if no packet has arrived sleep 2.50 ms */
		if ( data_spsc_ring_pop( &th->fifo, &pdata ) != 0 ) {
			tv.tv_sec = 0;
			tv.tv_usec = 250;
			//fprintf(stdout, "No more packets for thread %i --- waiting\n", th->thread_number);
			select(0, NULL, NULL, NULL, &tv);
		} else { /* else remove pkt head from list and process it */
			pkt = (struct packet_element *) pdata;
			/* is it a dummy packet ? => means thread must exit */
			if ( likely(pkt->data != NULL )) {
				packet_process(th->mmt_handler, &pkt->header,(u_char *) (&pkt->data[0]) );
				//increase nb packets processed by this thread
				th->nb_packets ++;
			}else{
				printf("thread %d : %"PRIu64" \n", th->thread_number, th->nb_packets );
				break;
			}
		}
	}

	if(th->mmt_handler != NULL){
		radius_ext_cleanup(th->mmt_handler); // cleanup our event handler for RADIUS initializations
		flowstruct_cleanup(th->mmt_handler); // cleanup our event handler
		if (mmt_probe.mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, th);
		process_session_timer_handler(th->mmt_handler);
		mmt_close_handler(th->mmt_handler);
		th->mmt_handler = NULL;
	}

	sprintf(lg_msg, "Thread %i ended (%"PRIu64" packets)", th->thread_number, th->nb_packets);
	//printf("Thread %i ended (%"PRIu64" packets)\n", th->thread_number, nb_pkts);
	mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_T_END, lg_msg);
	//fprintf(stdout, "Thread %i ended (%u packets)\n", th->thread_number, nb_pkts);
	return NULL;
}

struct dispatcher_struct {
	char * filename;
	pthread_t handle;
	int nb;
};

void process_trace_file(char * filename, mmt_probe_struct_t * mmt_probe) {
	int i;
	struct dispatcher_struct dispatcher[2];

	uint64_t packets_count = 0;
	pcap_t *pcap;
	const u_char *data;
	struct pkthdr header;
	struct pcap_pkthdr pkthdr;
	char errbuf[1024];
	//char mmt_errbuf[1024];
	char lg_msg[1024];
	struct smp_thread *th;
	static uint32_t p_hash = 0;
	static struct packet_element *pkt;
	static void *pdata;


	//Initialise MMT_Security
	if(mmt_probe->mmt_conf->security_enable==1)
		init_mmt_security(mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->properties_file,(void *)mmt_probe->smp_threads );
	//End initialise MMT_Security

	if (mmt_probe->mmt_conf->thread_nb == 1) {

		pcap = pcap_open_offline(filename, errbuf); // open offline trace

		if (!pcap) { /* pcap error ? */
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

			if(time(NULL)- mmt_probe->smp_threads->last_stat_report_time >= mmt_probe->mmt_conf->stats_reporting_period){
				mmt_probe->smp_threads->last_stat_report_time =time(NULL);
				process_session_timer_handler(mmt_probe->smp_threads->mmt_handler);
				if (mmt_probe->mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *)mmt_probe->smp_threads);
			}
			//if(time(NULL)- mmt_probe->smp_threads->last_msg_report_time >= mmt_probe->mmt_conf->sampled_report_period){
			//	mmt_probe->smp_threads->last_msg_report_time = time(NULL);
			//}
			//Call mmt_core function that will parse the packet and analyse it.

			if (!packet_process(mmt_probe->smp_threads->mmt_handler, &header, data)) {
				sprintf(lg_msg, "MMT Extraction failure! Error while processing packet number %"PRIu64"", packets_count);
				mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_E_PROCESS_ERROR, lg_msg);
			}
			packets_count++;
		}
		pcap_close(pcap);
		sprintf(lg_msg, "End processing trace file: %s", filename);
		mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_END_PROCESS_TRACE, lg_msg);
	}else {//We have more than one thread for processing packets! dispatch the packet to one of them
		pcap = pcap_open_offline(filename, errbuf); // open offline trace

		if (!pcap) { /* pcap error ? */
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
				for( i=0; i<mmt_probe->mmt_conf->thread_nb; i++){
					th = &mmt_probe->smp_threads[i];
					if( data_spsc_ring_get_tmp_element( &th->fifo, &pdata ) != 0)
						continue;

					pkt = (struct packet_element *) pdata;
					/* fill smp_pkt fields and copy packet data from pcap buffer */
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

			if( data_spsc_ring_get_tmp_element( &th->fifo, &pdata ) != 0)
				return;

			pkt = (struct packet_element *) pdata;
			/* fill smp_pkt fields and copy packet data from pcap buffer */
			pkt->header.len    = pkthdr.len;
			pkt->header.caplen = pkthdr.caplen;
			pkt->header.ts     = pkthdr.ts;
			pkt->data          = (u_char *)( &pkt[ 1 ]); //put data in the same memory segment but after sizeof( pkt )
			memcpy(pkt->data, data, pkthdr.caplen);
			while (  (is_queue_full = data_spsc_ring_push_tmp_element( &th->fifo )) != 0 ){
				usleep(100);
				//nb_packets_dropped_by_mmt ++;
				//th->nb_dropped_packets ++;

			}
		}
	}
}

//BW: TODO: add the pcap handler to the mmt_probe (or internal structure accessible from it) in order to be able to close it here

void cleanup(int signo) {
	mmt_probe_context_t * mmt_conf = mmt_probe.mmt_conf;
	int i;
	
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
	   (void) fprintf(stderr, "%12d packets dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
	   (void) fprintf(stderr, "%12"PRIu64" packets dropped by MMT (%3.2f%%) \n", nb_packets_dropped_by_mmt, nb_packets_dropped_by_mmt * 100.0 /  pcs.ps_recv );
	   fflush(stderr);
   }
   if( mmt_conf->thread_nb == 1)
	   (void) fprintf(stderr, "%12"PRIu64" packets processed by MMT (%3.2f%%) \n", nb_packets_processed_by_mmt, nb_packets_processed_by_mmt * 100.0 /  pcs.ps_recv );
   else
	   for (i = 0; i < mmt_conf->thread_nb; i++)
		   (void) fprintf( stderr, "- thread %2d processed %12"PRIu64" packets, dropped %12"PRIu64"\n",
				   mmt_probe.smp_threads[i].thread_number, mmt_probe.smp_threads[i].nb_packets, mmt_probe.smp_threads[i].nb_dropped_packets );
   fflush(stderr);
#ifdef RHEL3
	pcap_close(handle);
#endif /* RHEL3 */
}

void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *data) {
	struct smp_thread *th;
	struct pkthdr header;
	static uint32_t p_hash = 0;
	static void *pdata;
	static struct packet_element *pkt;
	
	if (mmt_probe.mmt_conf->thread_nb == 1) {

		header.ts = pkthdr->ts;
		header.caplen = pkthdr->caplen;
		header.len = pkthdr->len;
		header.user_args = NULL;

		if(time(NULL)- mmt_probe.smp_threads->last_stat_report_time  >= mmt_probe.mmt_conf->stats_reporting_period){
			mmt_probe.smp_threads->last_stat_report_time = time(NULL);
			process_session_timer_handler(mmt_probe.smp_threads->mmt_handler);
			if (mmt_probe.mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *)mmt_probe.smp_threads);
		}
		//if(time(NULL)- mmt_probe.smp_threads->last_msg_report_time >= mmt_probe.mmt_conf->sampled_report_period){
		//	mmt_probe.smp_threads->last_msg_report_time = time(NULL);
			//flush_messages_to_file_thread((void *)mmt_probe.smp_threads);
		//}

		if (!packet_process(mmt_probe.smp_threads->mmt_handler, &header, data)) {
			fprintf(stderr, "MMT Extraction failure! Error while processing packet number %"PRIu64"", nb_packets_processed_by_mmt);
			nb_packets_dropped_by_mmt ++;
		}
		nb_packets_processed_by_mmt ++;
	} else {//We have more than one thread for processing packets! dispatch the packet to one of them
		p_hash = get_packet_hash_number(data, pkthdr->caplen) % (mmt_probe.mmt_conf->thread_nb );
		th     = &mmt_probe.smp_threads[ p_hash ];

		if( data_spsc_ring_get_tmp_element( &th->fifo, &pdata ) != 0)
			return;

		pkt = (struct packet_element *) pdata;
		/* fill smp_pkt fields and copy packet data from pcap buffer */
		pkt->header.len    = pkthdr->len;
		pkt->header.caplen = pkthdr->caplen;
		pkt->header.ts     = pkthdr->ts;
		pkt->data          = (u_char *)( &pkt[ 1 ]); //put data in the same memory segment but after sizeof( pkt )
		memcpy(pkt->data, data, pkthdr->caplen);
		//pkt->data = data;

		if(  data_spsc_ring_push_tmp_element( &th->fifo ) != 0 ){
		//queue is full
			nb_packets_dropped_by_mmt ++;
			th->nb_dropped_packets ++;
			return;
		}
	}
}

/*
 * This thread reads stdin or the network and appends to the ring buffer
 */
void *Reader(void *arg) {
	struct mmt_probe_struct * mmt_probe = (struct mmt_probe_struct *) arg;

	char errbuf[PCAP_ERRBUF_SIZE]; /* error buffer */
	struct bpf_program fp; /* compiled filter program */
	bpf_u_int32 mask; /* subnet mask */
	bpf_u_int32 net; /* ip */
	int num_packets = -1; /* number of packets to capture */
	//int num_packets = 1000000; /* number of packets to capture */

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
		exit(EXIT_FAILURE);
	}
    pcap_set_snaplen(handle, d_snap_len);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 0);
    pcap_set_buffer_size(handle, 100*1000*1000);
    pcap_activate(handle);

	reader_ready = 1;

	/* make sure we're capturing on an Ethernet device */
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", mmt_probe->mmt_conf->input_source);
		exit(EXIT_FAILURE);
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
	if(mmt_probe->mmt_conf->security_enable==1)
		init_mmt_security( mmt_probe->smp_threads->mmt_handler, mmt_probe->mmt_conf->properties_file, (void *)mmt_probe->smp_threads );
	//End initialise MMT_Security

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

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

void terminate_probe_processing(int wait_thread_terminate) {
	char lg_msg[1024];
	mmt_probe_context_t * mmt_conf = mmt_probe.mmt_conf;
	int i;

	//For MMT_Security
	//To finish results file (e.g. write summary in the XML file)
	todo_at_end();
	//End for MMT_Security

	//Cleanup
	if (mmt_conf->thread_nb == 1) {
		//One thread for processing packets
		//Cleanup the MMT handler
		flowstruct_cleanup(mmt_probe.smp_threads->mmt_handler); // cleanup our event handler
		radius_ext_cleanup(mmt_probe.smp_threads->mmt_handler); // cleanup our event handler for RADIUS initializations
		process_session_timer_handler(mmt_probe.smp_threads->mmt_handler);
		if (mmt_conf->enable_proto_without_session_stats == 1)iterate_through_protocols(protocols_stats_iterator, (void *) mmt_probe.smp_threads);
		mmt_close_handler(mmt_probe.smp_threads->mmt_handler);
		report_all_protocols_microflows_stats((void *)mmt_probe.smp_threads);
		if (mmt_conf->output_to_file_enable == 1)flush_messages_to_file_thread((void *)mmt_probe.smp_threads);
		exit_timers();
		//Now report the microflows!

	} else {
		if (wait_thread_terminate) {
			/* Add a dummy packet at each thread packet list tail */

			for (i = 0; i < mmt_conf->thread_nb; i++) {

				pthread_spin_lock(&mmt_probe.smp_threads[i].lock);
				list_add_tail((struct list_entry *) &mmt_probe.smp_threads[i].null_pkt,
						(struct list_entry *) &mmt_probe.smp_threads[i].pkt_head);
				pthread_spin_unlock(&mmt_probe.smp_threads[i].lock);
			}
		}

		/* wait for all threads to complete */
		if (wait_thread_terminate) {
			for (i = 0; i < mmt_conf->thread_nb; i++) {
				pthread_join(mmt_probe.smp_threads[i].handle, NULL);
				report_all_protocols_microflows_stats(&mmt_probe.smp_threads[i]);
				if (mmt_conf->output_to_file_enable == 1)flush_messages_to_file_thread(&mmt_probe.smp_threads[i]);
				//flush_messages_to_file_thread(&mmt_probe.smp_threads[i]);
			}
			exit_timers();
		} else {
			//We might have catched a SEGV or ABORT signal.
			//We have seen the threads in deadlock situations.
			//Wait 30 seconds then cancel the threads
			//Once cancelled, join should give "THREAD_CANCELLED" retval
			sleep(30);
			for (i = 0; i < mmt_conf->thread_nb; i++) {
				int s;
				s = pthread_cancel(mmt_probe.smp_threads[i].handle);
				if (s != 0) {
					exit(0);
				}
			}
			for (i = 0; i < mmt_conf->thread_nb; i++) {
				//pthread_join(mmt_probe.smp_threads[i].handle, NULL);
				if (mmt_probe.smp_threads[i].mmt_handler != NULL) {
					flowstruct_cleanup(mmt_probe.smp_threads[i].mmt_handler); // cleanup our event handler
					radius_ext_cleanup(mmt_probe.smp_threads[i].mmt_handler); // cleanup our event handler for RADIUS initializations
					//process_session_timer_handler(mmt_probe.smp_threads[i].mmt_handler);
					//if (mmt_conf->enable_proto_without_session_stats == 1)iterate_through_protocols(protocols_stats_iterator, &mmt_probe.smp_threads[i]);
					mmt_close_handler(mmt_probe.smp_threads[i].mmt_handler);
					mmt_probe.smp_threads[i].mmt_handler = NULL;
				}
				report_all_protocols_microflows_stats(&mmt_probe.smp_threads[i].iprobe);
				exit_timers();
			}
		}
	}

	//Now close the reporting files.
	//Offline or Online processing
	if (mmt_conf->input_mode == OFFLINE_ANALYSIS||mmt_conf->input_mode == ONLINE_ANALYSIS) {
		if (mmt_conf->data_out_file) fclose(mmt_conf->data_out_file);
		sprintf(lg_msg, "Closing output results file");
		mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_CLOSE_OUTPUT, lg_msg);

	}
/*   char behaviour_command_str [500+1] = {0};
    int behaviour_valid = 0 ;
    int cr;
    //If the files are not created this will return error,remove_lock_file();
     if(mmt_conf->sampled_report == 1){
     	//flush_cache_and_exit_timers();
     }else if (mmt_conf->sampled_report == 0){
         if (mmt_conf->behaviour_enable == 1){
             behaviour_valid=snprintf(behaviour_command_str, MAX_FILE_NAME, "cp %s%s %s", mmt_conf->output_location,mmt_conf->data_out,mmt_conf->behaviour_output_location);
             behaviour_command_str[behaviour_valid]='\0';
             cr = system(behaviour_command_str);
             if (cr!=0){
                 fprintf(stderr,"\n5 Error code %d, while coping output file %s to %s ",cr, mmt_conf->output_location,mmt_conf->behaviour_output_location);
                 exit(1);
             }
             exit_timers();
         }

     }*/
//printf("HERE_close_extraction1\n");
	close_extraction();
//printf("HERE_close_extraction2\n");
	mmt_log(mmt_conf, MMT_L_INFO, MMT_E_END, "Closing MMT Extraction engine!");
	mmt_log(mmt_conf, MMT_L_INFO, MMT_P_END, "Closing MMT Probe!");
	if (mmt_conf->log_output) fclose(mmt_conf->log_output);
}

/* This signal handler ensures clean exits */
void signal_handler(int type) {
	static int i = 0;
	i++;
	char lg_msg[1024];
	fprintf(stderr, "\nreception of signal %d\n", type);
	fflush( stderr );
    cleanup( 0 );

    if (i == 1) {
        terminate_probe_processing(0);
        /*
                    if(strlen(mmt_probe.mmt_conf->input_f_name) > 1) {
                        if (remove(mmt_probe.mmt_conf->input_f_name) != 0) {
                            //fprintf(stdout, "Trace Error deleting file\n");
                            sprintf(lg_msg, "Error while deleting trace file: %s! File will remain on the system. Manual delete required!", mmt_probe.mmt_conf->input_f_name);
                            mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_DELETE, lg_msg);
                        } else {
                            sprintf(lg_msg, "Trace file %s deleted following the reception of error signal", mmt_probe.mmt_conf->input_f_name);
                            mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_TRACE_DELETE, lg_msg);
                            //fprintf(stdout, "Trace File %s successfully deleted\n", trace_file_name);
                        }
                    }
         */
    } else {
    	signal(SIGINT, signal_handler);
        sprintf(lg_msg, "reception of signal %i while processing a signal exiting!", type);
        /*
                mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_TERMINATION, "Multi signal received! cleaning up!");
                    if(strlen(mmt_probe.mmt_conf->input_f_name) > 1) {
                        if (remove(mmt_probe.mmt_conf->input_f_name) != 0) {
                            //fprintf(stdout, "Trace Error deleting file\n");
                            sprintf(lg_msg, "Error while deleting trace file: %s! File will remain on the system. Manual delete required!", mmt_probe.mmt_conf->input_f_name);
                            mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_DELETE, lg_msg);
                        } else {
                            sprintf(lg_msg, "Trace file %s deleted following the reception of error signal", mmt_probe.mmt_conf->input_f_name);
                            mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_TRACE_DELETE, lg_msg);
                            //fprintf(stdout, "Trace File %s successfully deleted\n", trace_file_name);
                        }
                    }
		 */
		exit(0);
	}

	switch (type) {
	case SIGSEGV:
		mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_SEGV_ERROR, "Segv signal received! cleaning up!");
		//terminate_probe_processing();
		//fprintf(stdout, "SEGMENTATION FAULT!!!! Exiting!!! \n");
		//Now delete the last input file if it is available. This is to avoid blocking situation in continuous trace file processing
		/*
                        if(strlen(mmt_probe.mmt_conf->input_f_name) > 1) {
                            if (remove(mmt_probe.mmt_conf->input_f_name) != 0) {
                                //fprintf(stdout, "Trace Error deleting file\n");
                                sprintf(lg_msg, "Error while deleting trace file: %s! File will remain on the system. Manual delete required!", mmt_probe.mmt_conf->input_f_name);
                                mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_DELETE, lg_msg);
                            } else {
                                sprintf(lg_msg, "Trace file %s deleted following the reception of error signal", mmt_probe.mmt_conf->input_f_name);
                                mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_TRACE_DELETE, lg_msg);
                                //fprintf(stdout, "Trace File %s successfully deleted\n", trace_file_name);
                            }
                        }
		 */
		exit(0);
	case SIGTERM:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION, "Termination signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(0);
	case SIGABRT:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION, "Abort signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(0);
	case SIGINT:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION, "Interruption Termination signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(0);
#ifndef _WIN32
	case SIGKILL:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION, "Kill signal received! Cleaning up before exiting!");
		//terminate_probe_processing();
		//fprintf(stdout, "Terminating\n");
		exit(0);
#endif
	default:
		mmt_log(mmt_probe.mmt_conf, MMT_L_WARNING, MMT_P_TERMINATION, "Received an unexpected signal!");
		exit(0);
	}
}

int main(int argc, char **argv) {
	char mmt_errbuf[1024];
	int i,j;
	char lg_msg[1024];
	sigset_t signal_set;
	char single_file [MAX_FILE_NAME+1]={0};
	pthread_mutex_init(&mutex_lock, NULL);
	pthread_spin_init(&spin_lock, 0);

	mmt_probe.smp_threads = NULL;
	mmt_probe.mmt_conf = NULL;

	mmt_probe_context_t * mmt_conf = get_probe_context_config();
	mmt_probe.mmt_conf = mmt_conf;

	parseOptions(argc, argv, mmt_conf);

	mmt_conf->log_output = fopen(mmt_conf->log_file, "a");


	sigfillset(&signal_set);
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);

	if (mmt_conf->sampled_report == 0) {
		int len=0;
		len=snprintf(single_file,MAX_FILE_NAME,"%s%s",mmt_conf->output_location,mmt_conf->data_out);
		single_file[len]='\0';
		update_reporting_time =time(0);

		mmt_conf->data_out_file = fopen(single_file, "w");

		if (mmt_conf->data_out_file == NULL){
			fprintf ( stderr , "\n[e] Error: %d creation of \"%s\" failed: %s\n" , errno ,single_file, strerror( errno ) );
			exit(1);
		}

		sprintf(lg_msg, "Open output results file: %s", single_file);
		mmt_log(mmt_conf, MMT_L_INFO, MMT_P_OPEN_OUTPUT, lg_msg);
	}
	is_stop_timer =0;

	if (license_expiry_check(0)==1){
		//exit(0);
	}

	mmt_log(mmt_conf, MMT_L_INFO, MMT_P_INIT, "MMT Probe started!");

	if (!init_extraction()) { // general ixE initialization
		fprintf(stderr, "MMT extract init error\n");
		mmt_log(mmt_conf, MMT_L_ERROR, MMT_E_INIT_ERROR, "MMT Extraction engine initialization error! Exiting!");
		return EXIT_FAILURE;
	}

	//For MMT_Security
	if (mmt_conf->security_enable==1)
		todo_at_start(mmt_conf->dir_out);
	//End for MMT_Security

	//Initialization
	if (mmt_conf->thread_nb == 1) {

		mmt_log(mmt_conf, MMT_L_INFO, MMT_E_INIT, "Initializating MMT Extraction engine! Single threaded operation.");
		mmt_probe.smp_threads = (struct smp_thread *) calloc(mmt_conf->thread_nb,sizeof (struct smp_thread));
		mmt_probe.smp_threads->last_stat_report_time = time(0);
		//mmt_probe.smp_threads->last_msg_report_time = time(0);
		//One thread for reading packets and processing them
		//Initialize an MMT handler
		mmt_probe.smp_threads->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
		if (!mmt_probe.smp_threads->mmt_handler) { /* pcap error ? */
			fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
			mmt_log(mmt_conf, MMT_L_ERROR, MMT_E_INIT_ERROR, "MMT Extraction handler initialization error! Exiting!");
			return EXIT_FAILURE;
		}

		//mmt_probe.iprobe.instance_id = 0;
		mmt_probe.smp_threads->thread_number = 0;
		for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
			reset_microflows_stats(&mmt_probe.smp_threads->iprobe.mf_stats[i]);
			mmt_probe.smp_threads->iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
			mmt_probe.smp_threads->iprobe.mf_stats[i].application_id = i;
		}
		mmt_probe.smp_threads->iprobe.instance_id = mmt_probe.smp_threads->thread_number;
		mmt_probe.smp_threads->thread_number = 0;

		pthread_spin_init(&mmt_probe.smp_threads->lock, 0);
		// customized packet and session handling functions are then registered
		if(mmt_probe.mmt_conf->enable_flow_stats) {
			register_session_timer_handler(mmt_probe.smp_threads->mmt_handler,print_ip_session_report,(void *) mmt_probe.smp_threads);
			register_session_timeout_handler(mmt_probe.smp_threads->mmt_handler, classification_expiry_session, (void *) mmt_probe.smp_threads);
			flowstruct_init((void *)mmt_probe.smp_threads); // initialize our event handler
			if(mmt_conf->event_based_reporting_enable==1)event_reports_init((void *)mmt_probe.smp_threads); // initialize our event reports
			conditional_reports_init(mmt_probe.smp_threads->mmt_handler);// initialize our conditional reports
			if(mmt_conf->radius_enable==1)radius_ext_init((void *)mmt_probe.smp_threads); // initialize radius extraction and attribute event handler
		}

		proto_stats_init(mmt_probe.smp_threads->mmt_handler);


		mmt_log(mmt_conf, MMT_L_INFO, MMT_E_STARTED, "MMT Extraction engine! successfully initialized in a single threaded operation.");
	} else {
		//Multiple threads for processing the packets
		/*
		 * Array of list of packets for all threads
		 */
		sprintf(lg_msg, "Initializating MMT Extraction engine! Multi threaded operation (%i threads)", mmt_conf->thread_nb);
		mmt_log(mmt_conf, MMT_L_INFO, MMT_E_INIT, lg_msg);
		mmt_probe.smp_threads = (struct smp_thread *) calloc(mmt_conf->thread_nb, sizeof (struct smp_thread));
		/* run threads */
		for (i = 0; i < mmt_conf->thread_nb; i++) {
			init_list_head((struct list_entry *) &mmt_probe.smp_threads[i].pkt_head);
			pthread_spin_init(&mmt_probe.smp_threads[i].lock, 0);
			mmt_probe.smp_threads[i].thread_number = i;
			mmt_probe.smp_threads[i].last_stat_report_time = time(0);
			//mmt_probe.smp_threads[i].last_msg_report_time = time(0);
			mmt_probe.smp_threads[i].null_pkt.pkt.data = NULL;
			
			mmt_probe.smp_threads[i].nb_dropped_packets = 0;
			mmt_probe.smp_threads[i].nb_packets         = 0;

			if( data_spsc_ring_init( &mmt_probe.smp_threads[i].fifo, mmt_conf->thread_queue_plen, snap_len ) != 0 ){
				perror("Not enough memory. Please reduce thread-queue or thread-nb in .conf");
				//free memory allocated
				for(j=0; j<=i; j++)
					data_spsc_ring_free( &mmt_probe.smp_threads[j].fifo );
				exit( 1 );
			}
			
			pthread_create(&mmt_probe.smp_threads[i].handle, NULL,
					smp_thread_routine, &mmt_probe.smp_threads[i]);
		}
		sprintf(lg_msg, "MMT Extraction engine! successfully initialized in a multi threaded operation (%i threads)", mmt_conf->thread_nb);
		mmt_log(mmt_conf, MMT_L_INFO, MMT_E_STARTED, lg_msg);
	}
	if (mmt_conf->output_to_file_enable == 1)start_timer( mmt_probe.mmt_conf->sampled_report_period, flush_messages_to_file_thread, (void *) &mmt_probe);
	//Offline or Online processing
	if (mmt_conf->input_mode == OFFLINE_ANALYSIS) {
		process_trace_file(mmt_conf->input_source, &mmt_probe); //Process single offline trace
		//We don't close the files here because they will be used when the handler is closed to report still to timeout flows
	}else if (mmt_conf->input_mode == ONLINE_ANALYSIS) {

		process_interface(mmt_conf->input_source, &mmt_probe); //Process single offline trace
		//We don't close the files here because they will be used when the handler is closed to report still to timeout flows
	}

	terminate_probe_processing(1);

	//printf("Process Terimated successfully\n");
	return EXIT_SUCCESS;
}

