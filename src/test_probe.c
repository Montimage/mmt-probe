
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <time.h>
#include "mmt_core.h"
#include "mmt/tcpip/mmt_tcpip.h"

#ifdef _WIN32
#include <ws2tcpip.h>
#include <windows.h>
#ifndef socklen_t
typedef int socklen_t;
#define socklen_t socklen_t
#endif
#else
#include <arpa/inet.h> //inet_ntop
#include <netinet/in.h>
#endif

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

struct rtp_reporting_struct {
			uint32_t jitter;
	        uint32_t loss;
	        uint32_t unorder;
	        uint32_t burst_loss;
	        double quality_index;

};

void quality_handler_function(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {
    struct rtp_reporting_struct * rtp_struct = (struct rtp_reporting_struct *) ipacket->session->user_data;
    if (rtp_struct == NULL) {
        return;
    }

    rtp_struct->quality_index = *((double *) attribute->data);

 printf ("%.3f",rtp_struct->jitter );
 printf ("%i",rtp_struct->loss);
 printf ("%i",rtp_struct->unorder);
 printf ("%i",rtp_struct->burst_loss);
 printf ("%i",rtp_struct->quality_index);

}

void packet_handler_function(const ipacket_t * ipacket, u_char * user_args) {
    int rtp_index = get_protocol_index_by_name(ipacket, "RTP");
    if (rtp_index != -1) {
        struct rtp_reporting_struct * rtp_struct = (struct rtp_reporting_struct *) ipacket->session->user_data;

        if (rtp_struct == NULL) {
            return;
        }
        unsigned * jitter;
        unsigned short * loss, * unorder, * order_err, * nb_burst, * duplicate;

        jitter = get_attribute_extracted_data_by_name("RTP", "jitter");
        loss = get_attribute_extracted_data_by_name("RTP", "loss");
        unorder = get_attribute_extracted_data_by_name("RTP", "unorder");
        nb_burst = get_attribute_extracted_data_by_name("RTP", "burst_loss");




        if (jitter) {
            rtp_struct->jitter = *jitter;
        }
        if (loss) {
            rtp_struct->loss += *loss;
        }
        if (unorder) {
            rtp_struct->unorder += *unorder;
        }

        if (nb_burst) {
            rtp_struct->burst_loss += 1;
        }

    }
}



int main(int argc, const char **argv) {
    mmt_handler_t *mmt_handler;
    char mmt_errbuf[1024];

    int packets_count = 0;
    pcap_t *pcap;
    const u_char *data;
    struct pkthdr header;
    struct pcap_pkthdr pkthdr;
    char errbuf[1024];

    if (argc < 2) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    pcap = pcap_open_offline(argv[1], errbuf); // open offline trace

    //pcap = pcap_open_offline("../mmt_dpi_test/imesh_p2p.pcap", errbuf); // open offline trace
    if (!pcap) { /* pcap error ? */
        fprintf(stderr, "pcap_open: %s\n", errbuf);
        return EXIT_FAILURE;
    }


    if (!init_extraction()) { // general ixE initialization
        fprintf(stderr, "MMT extract init error\n");
        return EXIT_FAILURE;
    }

    //Initialize an MMT handler
    mmt_handler = mmt_init_handler(DLT_EN10MB, 0, mmt_errbuf);
    if (!mmt_handler) { /* pcap error ? */
        fprintf(stderr, "MMT handler init failed for the following reason: %s\n", mmt_errbuf);
        return EXIT_FAILURE;
    }

    // customized packet and session handling functions are then registered

    register_packet_handler(mmt_handler, 1, packet_handler_function, NULL);
    register_attribute_handler_by_name(mmt_handler, "RTP", "quality", quality_handler_function, NULL ,NULL);
    register_extraction_attribute_by_name(mmt_handler, "RTP", "jitter");
    register_extraction_attribute_by_name(mmt_handler, "RTP", "loss");
    register_extraction_attribute_by_name(mmt_handler, "RTP", "unorder");
    register_extraction_attribute_by_name(mmt_handler, "RTP", "burst_loss");


    while ((data = pcap_next(pcap, &pkthdr))) {
        header.ts = pkthdr.ts;
        header.caplen = pkthdr.caplen;
        header.len = pkthdr.len;
        //header.msg_type = 0;
        //if(0) {
        if (!packet_process(mmt_handler, &header, data)) {
            fprintf(stderr, "Error 106: Packet data extraction failure.\n");
        }
        packets_count++;
    }

    mmt_close_handler(mmt_handler);

        close_extraction();

    pcap_close(pcap);

    printf("Process Terimated successfully\n");
    return EXIT_SUCCESS;
}
