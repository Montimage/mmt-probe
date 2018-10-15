/*
 * pcap_split.c
 *
 *  Created on: Oct 11, 2018
 *          by: Huu Nghia
 *
 * Extract from a pcap files the packets containing given IPs
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

#define MAX_FILENAME_SIZE 256

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <ip 1>      : IP.\n");
	fprintf(stderr, "\t-j <ip 2>      : IP.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

/**
 * Parse option
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
