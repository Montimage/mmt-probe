#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include "mmt_core.h"
#include "processing.h"
#include <sys/time.h>
#include <time.h>


#define __STDC_FORMAT_MACROS
#include <inttypes.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

static int quiet;




typedef struct rtp_reporting_struct {
			uint32_t jitter;
	        uint32_t loss;
	        uint32_t unorder;
	        uint32_t burst_loss;
	        time_t last_report_time;

} rtp_reporting_struct_t;



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

void reset_metrics (rtp_reporting_struct_t * rtp_stat){

rtp_stat->burst_loss= 0;

rtp_stat->jitter= 0;

rtp_stat->loss= 0;

rtp_stat->unorder= 0;

}


void loss_handler_fct(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

	if(get_session_from_packet(ipacket) == NULL) return;
	rtp_reporting_struct_t *rtp_stat = (rtp_reporting_struct_t *) get_user_session_context_from_packet(ipacket);

	if (rtp_stat != NULL) {
	        uint16_t * rtploss = (uint16_t *) attribute->data;
	        if (rtploss != NULL) {
	            rtp_stat->loss += * rtploss;
	        }
	    }

}




/**
 *
 */
void jitter_handler_fct(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {

    //We should never get here, but who knows :)
	if(get_session_from_packet(ipacket) == NULL) return;

	rtp_reporting_struct_t *rtp_stat = (rtp_reporting_struct_t *) get_user_session_context_from_packet(ipacket);

	if (rtp_stat == NULL) {
	    rtp_stat = malloc(sizeof (rtp_reporting_struct_t));
        if (rtp_stat == NULL) {

			        printf("Memory allocation failed when creating a new file reporting struct! This flow will be ignored! Sorry!");
			        return;
			    }

         memset(rtp_stat, '\0', sizeof (rtp_reporting_struct_t));
         rtp_stat->last_report_time = ipacket->p_hdr->ts.tv_sec;
         set_user_session_context(get_session_from_packet(ipacket), rtp_stat);


	}

	uint16_t * rtpjitter = (uint16_t *) attribute->data;
	if (rtpjitter != NULL) {
		rtp_stat->jitter = *rtpjitter;
	}

	if ((ipacket->p_hdr->ts.tv_sec - rtp_stat->last_report_time) >= 5) {

		printf("\nloss=%u,jitter=%u, unorder=%u, burstloss=%u\n ",rtp_stat->loss,rtp_stat->jitter,rtp_stat->unorder,rtp_stat->burst_loss);

		rtp_stat->last_report_time = ipacket->p_hdr->ts.tv_sec;
		reset_metrics(rtp_stat);
	}
}
void unorder_handler_fct(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {


	if(get_session_from_packet(ipacket) == NULL) return;

	rtp_reporting_struct_t *rtp_stat = (rtp_reporting_struct_t *) get_user_session_context_from_packet(ipacket);

	if (rtp_stat != NULL) {
	        uint16_t * rtpunorder = (uint16_t *) attribute->data;
	        if (rtpunorder != NULL) {
	            rtp_stat->unorder += * rtpunorder;
	        }
	    }

}

void burstloss_handler_fct(const ipacket_t * ipacket, attribute_t * attribute, void * user_args) {


	if(get_session_from_packet(ipacket) == NULL) return;
	rtp_reporting_struct_t *rtp_stat = (rtp_reporting_struct_t *) get_user_session_context_from_packet(ipacket);

	if (rtp_stat != NULL) {
	        uint16_t * rtpburstloss = (uint16_t *) attribute->data;
	        if (rtpburstloss != NULL) {
	            rtp_stat->burst_loss += * rtpburstloss;
	        }
	    }
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


    register_attribute_handler_by_name(mmt_handler, "RTP", "loss", loss_handler_fct, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "RTP", "jitter", jitter_handler_fct, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "RTP", "unorder", unorder_handler_fct, NULL, NULL);
    register_attribute_handler_by_name(mmt_handler, "RTP", "burst_loss", burstloss_handler_fct, NULL, NULL);

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

