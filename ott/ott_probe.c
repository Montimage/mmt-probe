/////

//gcc -g -o ott_probe ott_probe.c  -lmmt_core -ldl -lpcap -lpthread

//////
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

static int quiet;

void usage(const char * prg_name) {
    fprintf(stderr, "%s [<option>]\n", prg_name);
    fprintf(stderr, "Option:\n");
    fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
    fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
    fprintf(stderr, "\t-q             : Be quiet (no output whatsoever, helps profiling).\n");
    fprintf(stderr, "\t-h             : Prints this help.\n");
    exit(1);
}

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
void generic_attribute_event_handler(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    (void) mmt_attr_format(stdout, attribute);
}

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
    if (attribute->id < 1000)
        register_attribute_handler(
            args,
            proto_id, attribute->id,
            generic_attribute_event_handler,
            NULL /* Will be ignored, should be set to NULL */,
            NULL
            );
}

void protocols_iterator(uint32_t proto_id, void * args) {
    //iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
    if (proto_id == 625) {
        iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
    }
}

void packet_handler(const ipacket_t * ipacket, u_char * args) {
    printf("===================== Packet id %lu\n", ipacket->packet_id);
}

void live_capture_callback(u_char *user, const struct pcap_pkthdr *p_pkthdr, const u_char *data) {

    mmt_handler_t *mmt = (mmt_handler_t*) user;

    struct pkthdr header;
    header.ts = p_pkthdr->ts;
    header.caplen = p_pkthdr->caplen;
    header.len = p_pkthdr->len;
    if (!packet_process(mmt, &header, data)) {
        fprintf(stderr, "Packet data extraction failure.\n");
    }
}

int main(int argc, char** argv) {
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];

    pcap_t *pcap;
    const unsigned char *data;
    struct pcap_pkthdr p_pkthdr;
    char errbuf[1024];
    char filename[MAX_FILENAME_SIZE + 1];
    int type;

    struct pkthdr header;

    quiet = 0;
    parseOptions(argc, argv, filename, &type);

    init_extraction();

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    iterate_through_protocols(protocols_iterator, mmt_handler);

    //Register a packet handler, it will be called for every processed packet
    //register_packet_handler(mmt_handler, 1, debug_extracted_attributes_printout_handler /* built in packet handler that will print all of the attributes */, &quiet);

    //Register a packet handler to periodically report protocol statistics
    //register_packet_handler(mmt_handler, 2, packet_handler /* built in packet handler that will print all of the attributes */, mmt_handler);

    if (type == TRACE_FILE) {
        pcap = pcap_open_offline(filename, errbuf); // open offline trace
        if (!pcap) { /* pcap error ? */
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }

        uint32_t id = 0;
        while ((data = pcap_next(pcap, &p_pkthdr))) {
            
            header.ts = p_pkthdr.ts;
            header.caplen = p_pkthdr.caplen;
            header.len = p_pkthdr.len;
            //printf("===================== Packet id %u\n", id);
            if (!packet_process(mmt_handler, &header, data)) {
                fprintf(stderr, "Packet data extraction failure.\n");
            }
            id++;
        }
    } else {
        pcap = pcap_open_live(filename, MTU_BIG, 1, 1000, errbuf);
        if (!pcap) {
            fprintf(stderr, "pcap_open failed for the following reason: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        (void) pcap_loop(pcap, -1, &live_capture_callback, (u_char*) mmt_handler);
    }

    mmt_close_handler(mmt_handler);

    close_extraction();

    pcap_close(pcap);

    return EXIT_SUCCESS;
}

