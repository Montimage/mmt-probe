/**
 *
 * Showing the handler of the packets in the order after doing reorder
 *
 * Compile this example with:
 *
 * $ gcc -g -o packet_order packet_order.c -I /opt/mmt/dpi/include -I /opt/mmt/reassembly/include -L /opt/mmt/dpi/lib -L /opt/mmt/reassembly/lib  -lmmt_core -lmmt_reassembly -ldl -lpcap -lpthread
 *
 *
 * And get a data file (.pcap file) by using wireShark application to capture some packet.
 *
 * Then execute the program:
 *
 * $ ./packet_order -t trace_file.pcap
 *
 * The expected result is the process of the packet in the order
 *
 * That is it!
 *
 */

 #include <stdio.h>
 #include <stdlib.h>
 #include <pcap.h>
 #include <string.h>
 #include <unistd.h>
 #include <sys/types.h>
 #include <sys/stat.h>
 #include <sys/time.h>
 #include <fcntl.h>
 #include <getopt.h>
 #include <signal.h>
 #include <errno.h>

 #ifndef __FAVOR_BSD
 # define __FAVOR_BSD
 #endif
 #include "mmt_core.h"
 #include "tcpip/mmt_tcpip.h"
 #include "mmt_reassembly.h"
 #define MAX_FILENAME_SIZE 256
 #define TRACE_FILE 1
 #define LIVE_INTERFACE 2
 #define MTU_BIG (16 * 1024)

 static int quiet;


/**
 * Show packet id before the packets have been reordered
 * @param ipacket   packet
 * @param user_args user data
 * @return
 */
 int packet_handler_before_ordering(const ipacket_t * ipacket, void * user_args){
    printf("[debug] BEFORE: %lu\n",ipacket->packet_id);
    return 0;
}

/**
 * Show packet id after the packets have been reordered
 * @param ipacket   packet
 * @param user_args user data
 */
 int packet_handler_after_ordering(const ipacket_t * ipacket, void * user_args){
    printf("[debug] AFTER: %lu\n",ipacket->packet_id);
    return 0;
}



void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-q             : Be quiet (no output whatsoever, helps profiling).\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

/**
 * Parse option
 * @param argc     [description]
 * @param argv     [description]
 * @param filename [description]
 * @param type     [description]
 */
void parseOptions(int argc, char ** argv, char * filename, int * type) {
    int opt, optcount = 0;
    while ((opt = getopt(argc, argv, "t:i:qh")) != EOF) {
        switch (opt) {
            case 't':
            optcount++;
            if (optcount > 1) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = TRACE_FILE;
            break;
            case 'i':
            optcount++;
            if (optcount > 1) {
                usage(argv[0]);
            }
            strncpy((char *) filename, optarg, MAX_FILENAME_SIZE);
            *type = LIVE_INTERFACE;
            break;
            case 'q':
            quiet = 1;
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

/**
 * Live capture callback function
 * @param user     [description]
 * @param p_pkthdr [description]
 * @param data     [description]
 */
void live_capture_callback( u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data )
{
    mmt_handler_t *mmt = (mmt_handler_t*)user;
    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process( mmt, &header, data )) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}


int main(int argc, char ** argv){
    mmt_handler_t *mmt_handler;// MMT handler
    char mmt_errbuf[1024];
    struct pkthdr header; // MMT packet header

    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];

    quiet = 0;
    parseOptions(argc, argv, filename, &type);

    //Initialize MMT
    init_extraction();

    //Initialize MMT handler
    mmt_handler =mmt_init_handler(DLT_EN10MB,0,mmt_errbuf);
    if(!mmt_handler){
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
        return EXIT_FAILURE;
    }

    init_reassembly(mmt_handler,packet_handler_after_ordering);

    register_packet_handler(mmt_handler,1,packet_handler_before_ordering, NULL);

    printf("Packet_id, MAC source, MAC destination\n");
    if (type == TRACE_FILE) {
        pcap = pcap_open_offline(filename, errbuf); // open offline trace
        if (!pcap) { /* pcap error ? */
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        while ((data = pcap_next(pcap, &p_pkthdr))) {
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
        }
    } else {
        pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        (void)pcap_loop( pcap, -1, &live_capture_callback, (u_char*)mmt_handler );
    }

    close_reassembly();
    //Close the MMT handler
    mmt_close_handler(mmt_handler);

    //Close MMT
    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;

}
