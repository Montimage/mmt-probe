/**
* MMT-READER - show basic statistic of an Input traffic.
* The input traffic can be a pcap file or a network interface
*
* Compile this example with:
* Make sure you have mmt-dpi installed on your machine
*
* $ gcc -g -o mmtReader mmtReader.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
*
* Usage:
* ./mmtReader -t [PATH_TO_PCAP_FILE] <OPTION>
* sudo ./mmtReader -i [INTERFACE_NAME] <OPTION>
*
* Options:
*     -b [value] : Set buffer for pcap handler in realtime monitoring
*     -a         : Show protocol path
*     -h         : Show help
*
* That is it!
*
*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <errno.h>
#include <pcap.h>
#ifndef __FAVOR_BSD
# define __FAVOR_BSD
#endif
#include "mmt_core.h"
#include "tcpip/mmt_tcpip.h"

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2

mmt_handler_t *mmt_handler;// MMT handler
pcap_t *pcap; // Pcap handler
struct pcap_stat pcs; /* packet capture filter stats */
int pcap_bs = 0;
int port_classify = 1;
int hostname_classify = 1;
int ip_address_classify = 1;
int proto_path_detail = 0;
char filename[MAX_FILENAME_SIZE + 1]; // interface name or path to pcap file
int cleaned = 0;

// Global statistics
uint64_t nb_packets = 0;
uint64_t nb_ipv4_sessions = 0;
uint64_t nb_ipv6_sessions = 0;
uint64_t nb_protocols = 0;
uint64_t data_volume = 0;
struct timeval * init_time;
struct timeval * end_time;


/**
*
* Initialize a pcap handler
* @param  iname       interface name
* @param  buffer_size buffer size (MB)
* @param  snaplen     packet snaplen
* @return             NULL if cannot create pcap handler
*                     a pointer points to a new pcap handle
*/
pcap_t * init_pcap(char *iname, uint16_t buffer_size, uint16_t snaplen){
    pcap_t * my_pcap;
    char errbuf[1024];
    my_pcap = pcap_create(iname, errbuf);
    if (my_pcap == NULL) {
        fprintf(stderr, "[error] Couldn't open device %s\n", errbuf);
        exit(0);
    }
    pcap_set_snaplen(my_pcap, snaplen);
    pcap_set_promisc(my_pcap, 1);
    pcap_set_timeout(my_pcap, 0);
    pcap_set_buffer_size(my_pcap, buffer_size * 1000 * 1000);
    pcap_activate(my_pcap);

    if (pcap_datalink(my_pcap) != DLT_EN10MB) {
        fprintf(stderr, "[error] %s is not an Ethernet (Make sure you run with administrator permission! )\n", iname);
        exit(0);
    }
    return my_pcap;
}

/**
* Show help message
* @param prg_name program name
*/
void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-b <value>     : Set buffer for pcap handler\n");
    fprintf(stderr, "\t-a             : Show protocol statistic for each protocol path.\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
* parser input parameter
* @param argc     number of parameter
* @param argv     parameter string
* @param filename input source -> file name or interaface name
* @param type     TRACE_FILE or LIVE_INTERFACE
*/
void parseOptions(int argc, char ** argv, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:b:x:y:z:ha")) != EOF) {
        switch (opt) {
            case 't':
            optcount++;
            if (optcount > 6) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 6) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;

            case 'b':
            optcount++;
            if (optcount > 6) {
                usage(argv[0]);
            }
            pcap_bs = atoi(optarg);
            break;

            case 'a':
            optcount++;
            if (optcount > 6) {
                usage(argv[0]);
            }
            proto_path_detail = 1;
            break;
            case 'x':
            optcount++;
            if (optcount > 9)
            {
                usage(argv[0]);
            }
            ip_address_classify = atoi(optarg);
            break;
            case 'y':
            optcount++;
            if (optcount > 9)
            {
                usage(argv[0]);
            }
            hostname_classify = atoi(optarg);
            break;
            case 'z':
            optcount++;
            if (optcount > 9)
            {
                usage(argv[0]);
            }
            port_classify = atoi(optarg);
            break;
            case 'h':
            default: usage(argv[0]);
        }
    }

    if (filename == NULL || strcmp(filename, "") == 0) {
        if (*type == TRACE_FILE) {
            fprintf(stderr, "Missing trace file name\n");
        }
        if (*type == LIVE_INTERFACE) {
            fprintf(stderr, "Missing network interface name\n");
        }
        usage(argv[0]);
    }

    return;
}


struct stats{
	uint64_t packets;
};

/**
* Increase number of new IPV4 session has been created
* @param ipacket   [description]
* @param attribute [description]
* @param user_args [description]
*/
void new_ipv4_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    nb_ipv4_sessions++;
    struct stats *stat = malloc( sizeof( struct stat ));
    stat->packets = 0;

    set_user_session_context( ipacket->session, stat );
}

/**
* Increase number of new IPV6 session has been created
* @param ipacket   [description]
* @param attribute [description]
* @param user_args [description]
*/
void new_ipv6_session_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    nb_ipv6_sessions++;
}

/**
* Register extraction attributes
* @param attribute attribute to extract
* @param proto_id  protocol id
* @param args     user argument
*/
void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    register_extraction_attribute(args, proto_id, attribute->id);
}

/**
* Interate through all protocol attributes
* @param proto_id protocol id
* @param args     user argument
*/
void protocols_iterator(uint32_t proto_id, void * args) {
    iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

/**
* Analyse from an interface
* @param user     user argument
* @param p_pkthdr pcap header
* @param data     packet data
*/
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    // header.probe_id = 4;
    // header.source_id = 10;
    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

/**
* Packet handler
* - To update the total number of packet & total volume -> We can do it easily in pcap_loop but I also want to test our API to get the information from PROTO_META
* - Update the first packet arrival time and the last packet arrival time
* @param  ipacket   current packet
* @param  user_args [description]
* @return           [description]
*/
int packet_handler(const ipacket_t * ipacket, void * user_args){

    uint64_t *packet_count = (uint64_t *)get_attribute_extracted_data(ipacket,PROTO_META,PROTO_PACKET_COUNT);
    if(packet_count!=NULL){
        nb_packets = *packet_count;
    }

    uint64_t *data_count = (uint64_t *)get_attribute_extracted_data(ipacket,PROTO_META,PROTO_DATA_VOLUME);
    if(packet_count!=NULL){
        data_volume = *data_count;
    }
    if(ipacket->packet_id==1){
        struct timeval * first_time = (struct timeval * )get_attribute_extracted_data(ipacket,PROTO_META,PROTO_FIRST_PACKET_TIME);
        init_time = first_time;
    }

    struct timeval * last_time = (struct timeval * )get_attribute_extracted_data(ipacket,PROTO_META,PROTO_LAST_PACKET_TIME);
    end_time = last_time;

    return 0;
}

/**
* Print protocol path into a string
* @param  proto_hierarchy [description]
* @param  dest            [description]
* @return                 [description]
*/
int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy, char * dest) {
    int offset = 0;
    if (proto_hierarchy->len < 1) {
        offset += sprintf(dest, ".");
    } else {
        int index = 1;
        offset += sprintf(dest, "%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        index++;
        for (; index < proto_hierarchy->len && index < 16; index++) {
            offset += sprintf(&dest[offset], ".%s", get_protocol_name_by_id(proto_hierarchy->proto_path[index]));
        }
    }
    return offset;
}

typedef struct proto_info_struct{
    const char * name;
    uint64_t pkts;
    uint64_t volume;
    uint64_t payload;
    struct proto_info_struct * prev;
    struct proto_info_struct * next;
} proto_info_t;

static proto_info_t * head = NULL;

void insert_proto_info(proto_info_t * p_info){
    // First element
    if(head == NULL){
        head = p_info;
        return;
    }

    // Find and insert in the list
    proto_info_t * current = head;
    while(current!=NULL){
        if(p_info->pkts > current->pkts){
            p_info->next = current;
            p_info->prev = current->prev;
            if(current->prev !=NULL){
                current->prev->next = p_info;
            }else{
                head = p_info;
            }
            current->prev = p_info;
            return;
        }
        if(current->next == NULL){
            // insert in the end of the list
            current->next = p_info;
            p_info->prev = current;
            return;
        }
        current = current->next;
    }


}

/**
* Interate through all protocol attributes
* @param proto_id protocol id
* @param args     user argument
*/
void protocols_stats(uint32_t proto_id, void * args) {
    if(proto_id == 1) return; // Ignore PROTO_META
    proto_statistics_t * proto_stats = get_protocol_stats(args,proto_id);
    if(proto_stats!=NULL){
        nb_protocols++;
        proto_info_t * p_info = (proto_info_t * )malloc(sizeof(proto_info_t));
        memset(p_info,0,sizeof(proto_info_t));
        const char * proto_name = get_protocol_name_by_id(proto_id);
        p_info->name = proto_name;
        while (proto_stats != NULL) {
            //report the stats instance if there is anything to report
            if(proto_stats->touched) {
                p_info->pkts += proto_stats->packets_count;
                p_info->volume += proto_stats->data_volume;
                p_info->payload += proto_stats->payload_volume;
                if(proto_path_detail == 1){
                    proto_hierarchy_t proto_hierarchy = {0};
                    get_protocol_stats_path(mmt_handler, proto_stats, &proto_hierarchy);
                    char path[128];
                    proto_hierarchy_ids_to_str(&proto_hierarchy, path);
                    printf("%48s:%10lu %10lu %10lu %10lu.%lu %10lu.%lu\n",
                    path,
                    proto_stats->packets_count,
                    proto_stats->data_volume,
                    proto_stats->payload_volume,
                    proto_stats->first_packet_time.tv_sec, proto_stats->first_packet_time.tv_usec,
                    proto_stats->last_packet_time.tv_sec, proto_stats->last_packet_time.tv_usec );
                }
            }
            proto_stats = proto_stats->next;
        }
        insert_proto_info(p_info);
    }

}


void mmt_reader_stats(){
    printf("\n- - - - - - MMT-READER STATS - - - - -\n\n");
    if(proto_path_detail == 1) printf("Protocol statistics with the protocol path:\n\n");
    iterate_through_protocols(protocols_stats, mmt_handler);
    printf("\nProtocol statistics:\n\n");
    proto_info_t * current = head;
    while(current!=NULL){
        printf("%48s:%10lu %10lu %10lu\n",current->name,current->pkts,current->volume,current->payload);
        current = current->next;
        if(current!=NULL && current->prev!=NULL) {
            free(current->prev);
        }
    }
    printf(">>>>>> INPUT STATISTICS <<<<<< \n\n");
    printf("\tInput: %s\n", filename);
    printf("\tPackets: %lu\n",nb_packets );
    printf("\tData: %lu bytes\n",data_volume );
    printf("\tSessions: %lu\n",nb_ipv4_sessions + nb_ipv6_sessions );
    printf("\tProtocols: %lu\n",nb_protocols );
    printf("\tDuration: %lu seconds\n",end_time->tv_sec - init_time->tv_sec);
    printf("\tBandwidth: %.2f bytes/second\n",1.0*data_volume/(end_time->tv_sec - init_time->tv_sec));
    printf("\tpps: %.2f packets/second\n",1.0*nb_packets/(end_time->tv_sec - init_time->tv_sec));
    printf("\tfps: %.2f sessions/second\n\n",1.0*(nb_ipv4_sessions + nb_ipv6_sessions)/(end_time->tv_sec - init_time->tv_sec));
}

/**
* Clean resource when the program finished
*/
void clean() {

    if(cleaned == 1) return;
    cleaned = 1;
    // Print statistics

    mmt_reader_stats();

    // printf("\nINFO: Cleaning....\n");

    //Close the MMT handler
    mmt_close_handler(mmt_handler);
    // printf("INFO: Closed mmt_handler\n");

    //Close MMT
    close_extraction();
    // printf("INFO: Closed extraction \n");

    // Show pcap statistic if capture from an interface
    if (pcap_stats(pcap, &pcs) < 0) {
        // printf("INFO: pcap_stats does not exist\n");
        // (void) printf("INFO: pcap_stats: %s\n", pcap_geterr(pcap));
    } else {
        printf(">>>> PCAP STATISTICS <<<< \n\n");
        (void) printf("%12d Received\n", pcs.ps_recv);
        (void) printf("%12d Dropped by kernel (%3.2f%%)\n", pcs.ps_drop, pcs.ps_drop * 100.0 / pcs.ps_recv);
        (void) printf("%12d Dropped by driver (%3.2f%%)\n", pcs.ps_ifdrop, pcs.ps_ifdrop * 100.0 / pcs.ps_recv);
        fflush(stderr);
    }

    // printf("INFO: Closing pcaps...!\n");
    if (pcap != NULL) pcap_close(pcap);
    // printf("INFO: Finished cleaning....\n");
}

/**
* Handler signals during excutation time
* @param type signal type
*/
void signal_handler(int type) {
    printf("\nINFO: reception of signal %d\n", type);
    fflush( stderr );
    clean();
    exit(0);
}

static void _ending_session_handler(const mmt_session_t * dpi_session, void * user_args) {
	const proto_hierarchy_t *hierarchy = get_session_protocol_hierarchy( dpi_session );
	char path[128];
	proto_hierarchy_ids_to_str(hierarchy, path);
	uint64_t ul_packets = get_session_ul_cap_packet_count(dpi_session);
	uint64_t dl_packets = get_session_dl_cap_packet_count(dpi_session);
	uint64_t total_packets = get_session_packet_cap_count( dpi_session );

	uint64_t session_id = get_session_id( dpi_session );


	struct stats *stat = (struct stats *) get_user_session_context( dpi_session );

	if( session_id != 1 )
		return;

	struct timeval ts = get_session_last_activity_time( dpi_session );

	printf("%lu %s, ul: %3lu, dl: %3lu, tot: %3lu, session_id: %lu, %p, %lu.%06lu\n",
			total_packets - stat->packets,
			path, ul_packets, dl_packets,
			total_packets,

			session_id, dpi_session,
			ts.tv_sec, ts.tv_usec);



	stat->packets = total_packets;


//	hierarchy = get_session_proto_path_direction( dpi_session, 1 );
//	proto_hierarchy_ids_to_str(hierarchy, path);
//	printf("  %40s\n", path );
//
//	hierarchy = get_session_proto_path_direction( dpi_session, 0 );
//	proto_hierarchy_ids_to_str(hierarchy, path);
//	printf("  %40s\n", path );
}

/**
* Main program start from here
* @param  argc [description]
* @param  argv [description]
* @return      [description]
*/
int main(int argc, char ** argv) {
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    printf("|\t\t MONTIMAGE\n");
    printf("|\t MMT-SDK version: %s\n",mmt_version());
    printf("|\t %s: built %s %s\n", argv[0], __DATE__, __TIME__);
    printf("|\t http://montimage.com\n");
    printf("- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -\n");
    sigset_t signal_set;

    char mmt_errbuf[1024];
    int type = -1; // Online or offline mode

    // Parse option
    parseOptions(argc, argv, &type);

    //Initialize MMT
    init_extraction();

    //Initialize MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) {
        fprintf(stderr, "[error] MMT handler init failed for the following reason: %s\n", mmt_errbuf );
        return EXIT_FAILURE;
    }

//    if (ip_address_classify){
//        printf("Enable classification by IP address");
//        enable_ip_address_classify(mmt_handler);
//    }else{
//        disable_ip_address_classify(mmt_handler);
//    }
//
//    if (hostname_classify)
//    {
//        printf("Enable classification by Hostname");
//        enable_hostname_classify(mmt_handler);
//    }
//    else
//    {
//        disable_hostname_classify(mmt_handler);
//    }
//
//    if (port_classify)
//    {
//        printf("Enable classification by Port number");
//        enable_port_classify(mmt_handler);
//    }
//    else
//    {
//        disable_port_classify(mmt_handler);
//    }
    // Interate throught protocols to register extract all attributes of all protocols
    iterate_through_protocols(protocols_iterator, mmt_handler);
    register_packet_handler(mmt_handler, 1, packet_handler, NULL);
    // Register the callback function when there is a new session has been created
    register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION, new_ipv4_session_handler, NULL,NULL);
    register_attribute_handler(mmt_handler, PROTO_IPV6, PROTO_SESSION, new_ipv6_session_handler, NULL,NULL);


//	if( !register_session_timeout_handler( mmt_handler, _ending_session_handler, NULL )){
//		printf( "Cannot register handler for processing a session at ending" );
//		return EXIT_FAILURE;
//	}

	if( !register_session_timer_handler( mmt_handler, _ending_session_handler, NULL )){
		printf( "Cannot register handler for processing a session at ending" );
		return EXIT_FAILURE;
	}


    // Handle signal
    sigfillset(&signal_set);
    signal(SIGINT, signal_handler);

    if (type == TRACE_FILE) {
        // OFFLINE mode
        struct pkthdr header; // MMT packet header
        struct pcap_pkthdr p_pkthdr;
        pcap = pcap_open_offline(filename, mmt_errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason\n");
            return EXIT_FAILURE;
        }
        uint32_t last_ts = 0;
        const u_char *data = NULL;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }

            if( last_ts == 0 )
            	last_ts = p_pkthdr.ts.tv_sec ;
            //do session report each second
            else if( p_pkthdr.ts.tv_sec >= last_ts + 5 ){
            	//push statistic
            	process_session_timer_handler( mmt_handler );
            	last_ts = p_pkthdr.ts.tv_sec ;
            }

        }
//        process_session_timer_handler( mmt_handler );
    } else if(type == LIVE_INTERFACE){
        if(pcap_bs == 0){
            printf("INFO: Use default buffer size: 50 (MB)\n");
        }else{
            printf("INFO: Use buffer size: %d (MB)\n",pcap_bs);
        }
        // ONLINE MODE
        pcap = init_pcap(filename,pcap_bs,65535);

        if (!pcap) {
            fprintf(stderr, "[error] creating pcap failed for the following reason: %s\n", mmt_errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }else{
        usage(argv[0]);
    }

    clean();

    return EXIT_SUCCESS;

}
