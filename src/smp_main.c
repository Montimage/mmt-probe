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
#include <sched.h>
#include <sys/time.h>
#include <sys/types.h> //gettid
#include <sys/resource.h>
#include <unistd.h> //usleep, sleep
#include "mmt_core.h"
#include "processing.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define gettid() syscall(__NR_gettid)	/* missing in headers? */
#ifdef RHEL3 //RedHat Enterprise Linux 3
#define my_sched_setaffinity(a,b,c) sched_setaffinity(a, c)
#else
#define my_sched_setaffinity(a,b,c) sched_setaffinity(a, b, c)
#endif /* RHEL3 */

#define DLT_EN10MB 1    /* Ethernet (10Mb) */
#define READ_PRIO	-15	/* niceness value for Reader thread */
#define SNAP_LEN 65535	/* apparently what tcpdump uses for -s 0 */
#define READER_CPU	0	/* assign Reader thread to this CPU */
#define MAX_FILE_NAME 500
static int okcode  = EXIT_SUCCESS;
static int errcode = EXIT_FAILURE;

struct mmt_probe_struct {
    struct smp_thread *smp_threads;
    mmt_handler_t *mmt_handler; //For single threaded operations
    mmt_probe_context_t * mmt_conf;
    probe_internal_t iprobe;
    uint64_t packets_nb;
};

static struct mmt_probe_struct mmt_probe;

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

static void terminate_probe_processing(int wait_thread_terminate);


uint32_t get_2_power(uint32_t nb) {
    uint32_t ret = -1;
    while (nb != 0) {
        nb >>= 1;
        ret++;
    }
    return ret;
}

struct tmp_eth_hdr {
    uint8_t h_dest[6];
    uint8_t h_source[6];
    uint16_t h_proto;
};

struct tmp_vlan_hdr {
    uint16_t code;
    uint16_t h_proto;
};

int hash_packet(const u_char * packet, int len) {
    if (len < 38) return 0; //TODO: this is not elegant check IP, IPv6 etc.
    struct tmp_eth_hdr * eth = (struct tmp_eth_hdr *) packet;

    int ip_src_off, ip_dst_off;
    if (ntohs(eth->h_proto) == 0x0800) {
        ip_src_off = 26;
        ip_dst_off = 30;
    } else if ((ntohs(eth->h_proto) == 0x8100)) {
        ip_src_off = 30;
        ip_dst_off = 34;
    } else {
        return 0;
    }
    int a1 = *((int *) &packet[ip_src_off]);
    int a2 = *((int *) &packet[ip_dst_off]);


    if ((ntohl(a1) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
    	return ntohl(a1);
    }

    if ((ntohl(a2) & 0xFF000000 /* 255.0.0.0 */) == 0x0A000000 /* 10.0.0.0 */) {
        return ntohl(a2);
    }

    //a1 = (a1 & a2) ^ (a1 | a2);
    a1 = (a1 >> 24) + (a1 >> 16) + (a1 >> 8) + a1;
    a2 = (a2 >> 24) + (a2 >> 16) + (a2 >> 8) + a2;
    a1 = a1 + a2;

    return a1;
}

struct packet_element {
    struct pkthdr header;
    u_char *data;
};

/**
 * Double linked list structure
 */
struct list_entry {
    struct list_entry *next, *prev;
};

/**
 * List node initialization
 */
static inline void init_list_head(struct list_entry *list) {
    list->next = list;
    list->prev = list;
}

/**
 * Test if list is empty
 */
static inline int list_empty(struct list_entry *list) {
    return (list->next == list);
}

/**
 * Add a node at list tail
 */
static inline void list_add_tail(struct list_entry *new, struct list_entry *head) {
    new->next = head;
    head->prev->next = new;
    new->prev = head->prev;
    head->prev = new;
}

/**
 * Remove a node from list
 */
static inline void list_del(struct list_entry *entry) {
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
    entry->next = NULL;
    entry->prev = NULL;
}

/*
 * Packet with pointer on next packet
 * for list insertion
 */
struct smp_pkt {
    struct list_entry entry; /* list structure */
    struct packet_element pkt; /* real packet information */
};

/*
 * List of packets for a thread
 */
struct smp_thread {
    int thread_number;
    mmt_handler_t *mmt_handler;
    probe_internal_t iprobe;
    uint32_t queue_plen;
    uint32_t queue_blen;
    pthread_t handle; /* thread handle */
    pthread_spinlock_t lock; /* lock for concurrent access */
    struct smp_pkt pkt_head; /* pointer on first packet */
    struct smp_pkt null_pkt; /* Null packet used to indicate end of packet feeding for the thread. */
    time_t last_report_time;
};

/*
 * This callback will be called by ixE for packets completely processed.
 */
static void free_packet_element(void * packet) {
    if(packet)free(packet);
    packet = NULL;
}


static void *smp_thread_routine(void *arg) {
    struct timeval tv;
    struct smp_thread *th = (struct smp_thread *) arg;
    uint64_t nb_pkts = 0;
    struct smp_pkt *pkt_head;
    char mmt_errbuf[1024];
    char lg_msg[256];
    int quit = 0, i = 0;
    sprintf(lg_msg, "Starting thread %i", th->thread_number);

    mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_T_INIT, lg_msg);

    //Initialize an MMT handler
    //pthread_mutex_lock(&mutex_lock);
    th->mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    //pthread_mutex_unlock(&mutex_lock);

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
    	register_session_timer_handler(th->mmt_handler,print_ip_session_report,NULL);
        register_session_timeout_handler(th->mmt_handler, classification_expiry_session, &th->iprobe);
        flowstruct_init(th->mmt_handler); // initialize our event handler
        if(mmt_probe.mmt_conf->event_based_reporting_enable==1)event_reports_init(th->mmt_handler); // initialize our event reports
        conditional_reports_init(th->mmt_handler);// initialize our condition reports
        if(mmt_probe.mmt_conf->radius_enable==1)radius_ext_init(th->mmt_handler); // initialize radius extraction and attribute event handler
    }


        proto_stats_init(th->mmt_handler);

    	mmt_probe_context_t * probe_context = get_probe_context_config();
    	char message[MAX_MESS + 1];
    	th->last_report_time =time(NULL);

    while (!quit) {

        if(time(NULL)- th->last_report_time >= mmt_probe.mmt_conf->stats_reporting_period){
        	th->last_report_time=time(NULL);
            process_session_timer_handler(th->mmt_handler);
            if (probe_context->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *) th->mmt_handler);

        }
        pthread_spin_lock(&th->lock);
        /* if no packet has arrived sleep 2.50 ms */
        if (list_empty((struct list_entry *) &th->pkt_head)) {
            pthread_spin_unlock(&th->lock);
            tv.tv_sec = 0;
            tv.tv_usec = 2500;
            //fprintf(stdout, "No more packets for thread %i --- waiting\n", th->thread_number);
            select(0, NULL, NULL, NULL, &tv);
        } else { /* else remove pkt head from list and process it */
            pkt_head = (struct smp_pkt *) th->pkt_head.entry.next;
            list_del((struct list_entry *) pkt_head);
            //pthread_mutex_lock(& mutex_lock);//jeevan
            th->queue_plen -= 1;
            //pthread_mutex_unlock(& mutex_lock);
            th->queue_blen -= pkt_head->pkt.header.caplen;

            if ((int) th->queue_plen < 0) th->queue_plen = 0;
            if ((int) th->queue_blen < 0) th->queue_blen = 0;
            pthread_spin_unlock(&th->lock);
            /* is it a dummy packet ? => means thread must exit */
            quit = (pkt_head->pkt.data == NULL);
            if (!quit) {
                packet_process(th->mmt_handler, &pkt_head->pkt.header, pkt_head->pkt.data);
                free_packet_element((void *) pkt_head);
                nb_pkts++;
            }
        }
    }




    if(th->mmt_handler != NULL){
    	//pthread_spin_lock(&th->lock);
    	radius_ext_cleanup(th->mmt_handler); // cleanup our event handler for RADIUS initializations
    	flowstruct_cleanup(th->mmt_handler); // cleanup our event handler
    	//if (mmt_probe.mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *) th->mmt_handler);
        mmt_close_handler(th->mmt_handler);
        th->mmt_handler = NULL;
        //pthread_spin_unlock(&th->lock);
    }

    sprintf(lg_msg, "Thread %i ended (%"PRIu64" packets)", th->thread_number, nb_pkts);
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

static void *process_tracefile_thread_routine(void *arg);

void process_trace_file(char * filename, struct mmt_probe_struct * mmt_probe) {
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


    //Initialise MMT_Security
    if(mmt_probe->mmt_conf->security_enable==1)
        init_mmt_security( mmt_probe->mmt_handler, mmt_probe->mmt_conf->properties_file );
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
    	char message[MAX_MESS + 1];

        while ((data = pcap_next(pcap, &pkthdr))) {

            header.ts = pkthdr.ts;
            header.caplen = pkthdr.caplen;
            header.len = pkthdr.len;
            header.user_args = NULL;

            if(time(NULL)- update_reporting_time >= mmt_probe->mmt_conf->stats_reporting_period){
            	update_reporting_time=time(NULL);
                process_session_timer_handler(mmt_probe->mmt_handler);
                if (mmt_probe->mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *) mmt_probe->mmt_handler);

            }

            //Call mmt_core function that will parse the packet and analyse it.
            //If MMT_Security is being used:
            //   When a security property is satisfied or not, the callback
            //   function todo_when_property_is_satisfied_or_not will be executed.
            if (!packet_process(mmt_probe->mmt_handler, &header, data)) {
                sprintf(lg_msg, "MMT Extraction failure! Error while processing packet number %"PRIu64"", packets_count);
                mmt_log(mmt_probe->mmt_conf, MMT_L_ERROR, MMT_E_PROCESS_ERROR, lg_msg);
            }
            packets_count++;
        }
        pcap_close(pcap);
        sprintf(lg_msg, "End processing trace file: %s", filename);
        mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_END_PROCESS_TRACE, lg_msg);
    } else {
        sprintf(lg_msg, "Start processing trace file: %s", filename);
        mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_START_PROCESS_TRACE, lg_msg);
        for (i = 0; i < 2; i++) {
            dispatcher[i].filename = filename;
            dispatcher[i].nb = i;
            pthread_create(&dispatcher[i].handle, NULL, process_tracefile_thread_routine, &dispatcher[i]);
        }

        /* wait for the dispatching threads to complete */
        for (i = 0; i < 2; i++) {
            pthread_join(dispatcher[i].handle, NULL);
        }

        int i, processing_ongoing;
        struct timeval tv_start_watching, tv_next;
        gettimeofday(& tv_start_watching, NULL);
        do {
            processing_ongoing = 0;
            usleep(1000); //Give some time for the threads to finish processing the packets.
            for (i = 0; i < mmt_probe->mmt_conf->thread_nb; i++) {
            	//pthread_mutex_lock(& mutex_lock);
            	pthread_spin_lock(&mmt_probe->smp_threads[i].lock);
                processing_ongoing += mmt_probe->smp_threads[i].queue_plen;
                pthread_spin_unlock(&mmt_probe->smp_threads[i].lock);
                //pthread_mutex_unlock(& mutex_lock);
                //printf("processing_ongoing_th_nb %d = %d\n",i,processing_ongoing);
            }
            gettimeofday(& tv_next, NULL);
            if (tv_next.tv_sec - tv_start_watching.tv_sec > 120) {
                //We are bad, probably a thread is deadocked! exit
                terminate_probe_processing(0);
                exit(0);
            }
        } while (processing_ongoing);

        sprintf(lg_msg, "End processing trace file: %s", filename);
        mmt_log(mmt_probe->mmt_conf, MMT_L_INFO, MMT_P_END_PROCESS_TRACE, lg_msg);
    }
}

//BW: TODO: add the pcap handler to the mmt_probe (or internal structure accessible from it) in order to be able to close it here

void cleanup(int signo) {
    stop = 1;
    if (got_stats) return;
#ifndef RHEL3
    pcap_breakloop(handle);
#endif
    if (pcap_stats(handle, &pcs) < 0) {
        (void) fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(handle));
    } else got_stats = 1;
#ifdef RHEL3
    pcap_close(handle);
#endif /* RHEL3 */
}

void got_packet(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *data) {
    struct smp_thread *th;
    struct pkthdr header;
    static uint64_t packets_count = 0;
    char lg_msg[1024];
    int p_hash;

    if (mmt_probe.mmt_conf->thread_nb == 1) {

    	header.ts = pkthdr->ts;
        header.caplen = pkthdr->caplen;
        header.len = pkthdr->len;
        header.user_args = NULL;

        if(time(NULL)- update_reporting_time >= mmt_probe.mmt_conf->stats_reporting_period){
        	update_reporting_time=time(NULL);
        	process_session_timer_handler(mmt_probe.mmt_handler);
            if (mmt_probe.mmt_conf->enable_proto_without_session_stats ==1)iterate_through_protocols(protocols_stats_iterator, (void *) mmt_probe.mmt_handler);
        }

        if (!packet_process(mmt_probe.mmt_handler, &header, data)) {
            fprintf(stderr, "MMT Extraction failure! Error while processing packet number %"PRIu64"", packets_count);
        }
        packets_count++;
    } else {//We have more than one thread for processing packets! dispatch the packet to one of them
        struct smp_pkt * smp_pkt_instance;
        p_hash = hash_packet(data, pkthdr->caplen);
        if ((smp_pkt_instance = malloc(sizeof (struct smp_pkt) +pkthdr->caplen)) == NULL) {
            sprintf(lg_msg, "Memory error while processing packet nb %"PRIu64" from %s! Will wait one second and resume!", packets_count, mmt_probe.mmt_conf->input_source);
            mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_MEM_ERROR, lg_msg);
            sleep(1); //Sleep 1 second.
        } else {
            //check for license
            /* fill smp_pkt fields and copy packet data from pcap buffer */

            smp_pkt_instance->pkt.header.len = pkthdr->len;
            smp_pkt_instance->pkt.header.caplen = pkthdr->caplen;
            smp_pkt_instance->pkt.header.ts = pkthdr->ts;
            smp_pkt_instance->pkt.header.user_args = NULL;
            smp_pkt_instance->pkt.data = (unsigned char *) (&smp_pkt_instance[1]);
            memcpy(smp_pkt_instance->pkt.data, data, pkthdr->caplen);
            /* get thread destination structure */
            th = &mmt_probe.smp_threads[p_hash & (mmt_probe.mmt_conf->thread_nb - 1)];
            pthread_spin_lock(&th->lock);
            if (th->queue_blen > mmt_probe.mmt_conf->thread_queue_blen || th->queue_plen > mmt_probe.mmt_conf->thread_queue_plen) {
                //The packet will be dropped from the analysis
                sprintf(lg_msg, "Handler queue full error. Instance %i will drop packet nb %"PRIu64" from %s", th->thread_number, packets_count, mmt_probe.mmt_conf->input_source);
                mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_INSTANCE_QUEUE_FULL, lg_msg);
                if(smp_pkt_instance)free(smp_pkt_instance);
                smp_pkt_instance = NULL;
            } else {
                list_add_tail((struct list_entry *) smp_pkt_instance, (struct list_entry *) &th->pkt_head);
                th->queue_plen += 1;
                th->queue_blen += pkthdr->caplen;
            }
            pthread_spin_unlock(&th->lock);
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
#ifdef CPU_SET
    int rtid = gettid(); /* reader thread id */
    cpu_set_t csmask;
    CPU_ZERO(&csmask);
    CPU_SET(READER_CPU, &csmask);
    if (my_sched_setaffinity(rtid, sizeof (cpu_set_t), &csmask) != 0) {
        fprintf(stderr, "Reader could not set cpu affinity: %s\n", strerror(errno));
    }
    if (setpriority(PRIO_PROCESS, rtid, READ_PRIO) != 0) {
        fprintf(stderr, "Reader could not set scheduling priority: %s\n", strerror(errno));
    }
#else
    //replace with equivalent code for target OS or delete and run less optimally
#endif

    struct sigaction sa;
    sa.sa_handler = cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* allow signal to abort pcap read */

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);


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
    handle = pcap_open_live(mmt_probe->mmt_conf->input_source, d_snap_len, 1, 0, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    reader_ready = 1;

    /* make sure we're capturing on an Ethernet device */
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", mmt_probe->mmt_conf->input_source);
        exit(EXIT_FAILURE);
    }

    /* compile the filter expression */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    /* apply the compiled filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    //Initialise MMT_Security
    if(mmt_probe->mmt_conf->security_enable==1)
        init_mmt_security( mmt_probe->mmt_handler, mmt_probe->mmt_conf->properties_file );
    //End initialise MMT_Security

    /* now we can set our callback function */
    pcap_loop(handle, num_packets, got_packet, NULL);



    //fprintf(stderr, "\n%d packets captured\n", captured);
    if (ignored > 0) {
        fprintf(stderr, "%d packets ignored (too small to decapsulate)\n", ignored);
    }
    if (got_stats) {
        (void) fprintf(stderr, "%d packets received by filter\n", pcs.ps_recv);
        (void) fprintf(stderr, "%d packets dropped by kernel\n", pcs.ps_drop);
    }
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
    pthread_t reader_thread; //Live interface reader thread
    int rc;
    rc = pthread_create(&reader_thread, NULL, &Reader, (void *) mmt_probe);
    if (rc) {
        fprintf(stderr, "pthread_create error while creating interface reader\n");
        exit(1);
    }

    while (!stop) {
        usleep(500000);
    }
}

static void *process_tracefile_thread_routine(void *arg) {
    struct dispatcher_struct * dispatcher = (struct dispatcher_struct *) arg;

    uint64_t packets_count = 0;
    pcap_t *pcap;
    const u_char *data;
    struct pcap_pkthdr pkthdr;
    char errbuf[1024];
    char lg_msg[1024];
    struct smp_pkt *smp_pkt;
    struct smp_thread *th;

    pcap = pcap_open_offline(dispatcher->filename, errbuf); // open offline trace
    if (!pcap) { /* pcap error ? */
        sprintf(lg_msg, "Error while opening pcap file in dispatcher nb %i: %s --- error msg: %s", dispatcher->nb, dispatcher->filename, errbuf);
        printf("Error: Verify the name and the location of the trace file to be analysed \n ");
        mmt_log(mmt_probe.mmt_conf, MMT_L_ERROR, MMT_P_TRACE_ERROR, lg_msg);
        return &errcode;
    }

    sprintf(lg_msg, "Start dispatching packets from trace file: %s --- dispatcher %i", dispatcher->filename, dispatcher->nb);
    mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_START_PROCESS_TRACE, lg_msg);

    //Multiple threads for processing the packets
    /*
     * Array of list of packets for all threads
     */
    /* read packets */
    int p_hash;
    while ((data = pcap_next(pcap, &pkthdr))) {
        //check for license
    	//printf("dispatcher =%p\n",dispatcher);
        packets_count++;
        //printf("packets_count=%lu\n",packets_count);
        p_hash = hash_packet(data, pkthdr.caplen);
        if ((dispatcher->nb & p_hash) == (dispatcher->nb || (p_hash & 1))) {
            /* build a new smp_pkt structure + length for packet data */
            if ((smp_pkt = malloc(sizeof (struct smp_pkt) +pkthdr.caplen)) == NULL) {
                sprintf(lg_msg, "Memory error while processing packet nb %"PRIu64" from %s! Will wait one second and resume!", packets_count, dispatcher->filename);
                mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_MEM_ERROR, lg_msg);
                //fprintf(stderr, "Running out of memory when processing a new packet! Will wait one second now\n");
                sleep(1); //Sleep 1 second.
            } else {
                /* fill smp_pkt fields and copy packet data from
                pcap buffer */
                smp_pkt->pkt.header.len = pkthdr.len;
                smp_pkt->pkt.header.caplen = pkthdr.caplen;
                smp_pkt->pkt.header.ts = pkthdr.ts;
                smp_pkt->pkt.header.user_args = NULL;
                smp_pkt->pkt.data = (unsigned char *) (&smp_pkt[1]);
                memcpy(smp_pkt->pkt.data, data, pkthdr.caplen);

                /* get thread destination structure */
                //printf("Hash of packet nb %i : %i\n", packets_count, hash_packet(data, pkthdr.caplen));
                //th = &mmt_probe->smp_threads[packets_count & (mmt_probe->mmt_conf->thread_nb - 1)];
                th = &mmt_probe.smp_threads[p_hash & (mmt_probe.mmt_conf->thread_nb - 1)]; //get thread to assign a packet
                pthread_spin_lock(&th->lock);
                if (th->queue_blen > mmt_probe.mmt_conf->thread_queue_blen || th->queue_plen > mmt_probe.mmt_conf->thread_queue_plen) {
                    //The packet will be dropped from the analysis
                    sprintf(lg_msg, "Handler queue full error. Instance %i will drop packet nb %"PRIu64" from %s", th->thread_number, packets_count, dispatcher->filename);
                    mmt_log(mmt_probe.mmt_conf, MMT_L_EMERGENCY, MMT_P_INSTANCE_QUEUE_FULL, lg_msg);
                    if(smp_pkt)free(smp_pkt);
                    smp_pkt = NULL;
                } else {
                    list_add_tail((struct list_entry *) smp_pkt, (struct list_entry *) &th->pkt_head);
                    th->queue_plen += 1;
                    th->queue_blen += pkthdr.caplen;
                }
                pthread_spin_unlock(&th->lock);
            }
        }
    }
    pcap_close(pcap);
    sprintf(lg_msg, "End dispatching packets from trace file: %s --- Dispatcher %i", dispatcher->filename, dispatcher->nb);
    mmt_log(mmt_probe.mmt_conf, MMT_L_INFO, MMT_P_END_PROCESS_TRACE, lg_msg);

    return &okcode;
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
        flowstruct_cleanup(mmt_probe.mmt_handler); // cleanup our event handler
        radius_ext_cleanup(mmt_probe.mmt_handler); // cleanup our event handler for RADIUS initializations
        printf("mmt_conf->enable_proto_without_session_stats =%d\n",mmt_conf->enable_proto_without_session_stats);
        if (mmt_conf->enable_proto_without_session_stats == 1)iterate_through_protocols(protocols_stats_iterator, (void *) mmt_probe.mmt_handler);

        mmt_close_handler(mmt_probe.mmt_handler);
        //Now report the microflows!
        report_all_protocols_microflows_stats(&mmt_probe.iprobe);


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
                report_all_protocols_microflows_stats(&mmt_probe.smp_threads[i].iprobe);
            }
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
                    mmt_close_handler(mmt_probe.smp_threads[i].mmt_handler);
                    mmt_probe.smp_threads[i].mmt_handler = NULL;
                }
                report_all_protocols_microflows_stats(&mmt_probe.smp_threads[i].iprobe);
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
    char behaviour_command_str [500+1] = {0};
    int behaviour_valid = 0 ;
    int cr;
    //If the files are not created this will return error,remove_lock_file();
     if(mmt_conf->sampled_report == 1){
     	flush_cache_and_exit_timers();
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

     }

     close_extraction();

    mmt_log(mmt_conf, MMT_L_INFO, MMT_E_END, "Closing MMT Extraction engine!");

    mmt_log(mmt_conf, MMT_L_INFO, MMT_P_END, "Closing MMT Probe!");

    if (mmt_conf->log_output) fclose(mmt_conf->log_output);

}

/* This signal handler ensures clean exits */
void signal_handler(int type) {
    static int i = 0;
    i++;
    char lg_msg[1024];

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
    int i;
    char lg_msg[1024];
    sigset_t signal_set;
    char single_file [256+1]={0};
    pthread_mutex_init(&mutex_lock, NULL);
    pthread_spin_init(&spin_lock, 0);


    mmt_probe.smp_threads = NULL;
    mmt_probe.mmt_handler = NULL;
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
    start_timer( mmt_conf->sampled_report_period, flush_messages_to_file, NULL );

    if (license_expiry_check(0)==1) exit(0);

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
        //One thread for reading packets and processing them
        //Initialize an MMT handler
        mmt_probe.mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
        if (!mmt_probe.mmt_handler) { /* pcap error ? */
            fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
            mmt_log(mmt_conf, MMT_L_ERROR, MMT_E_INIT_ERROR, "MMT Extraction handler initialization error! Exiting!");
            return EXIT_FAILURE;
        }

        for (i = 0; i < PROTO_MAX_IDENTIFIER; i++) {
            reset_microflows_stats(&mmt_probe.iprobe.mf_stats[i]);
            mmt_probe.iprobe.mf_stats[i].application = get_protocol_name_by_id(i);
            mmt_probe.iprobe.mf_stats[i].application_id = i;
        }
        mmt_probe.iprobe.instance_id = 0;

        // customized packet and session handling functions are then registered
        if(mmt_probe.mmt_conf->enable_flow_stats) {
        	register_session_timer_handler(mmt_probe.mmt_handler,print_ip_session_report,NULL);
            register_session_timeout_handler(mmt_probe.mmt_handler, classification_expiry_session, &mmt_probe.iprobe);
            flowstruct_init(mmt_probe.mmt_handler); // initialize our event handler
            if(mmt_conf->event_based_reporting_enable==1)event_reports_init(mmt_probe.mmt_handler); // initialize our event reports
            conditional_reports_init(mmt_probe.mmt_handler);// initialize our conditional reports
            if(mmt_conf->radius_enable==1)radius_ext_init(mmt_probe.mmt_handler); // initialize radius extraction and attribute event handler
        }
        //if(mmt_conf->private_network_enable==1)private_network_handle(mmt_probe.mmt_handler);

            proto_stats_init(mmt_probe.mmt_handler);


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
            mmt_probe.smp_threads[i].null_pkt.pkt.data = NULL;
            pthread_create(&mmt_probe.smp_threads[i].handle, NULL,
                    smp_thread_routine, &mmt_probe.smp_threads[i]);
        }
        sprintf(lg_msg, "MMT Extraction engine! successfully initialized in a multi threaded operation (%i threads)", mmt_conf->thread_nb);
        mmt_log(mmt_conf, MMT_L_INFO, MMT_E_STARTED, lg_msg);
    }

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

