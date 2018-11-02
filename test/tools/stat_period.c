/*
 * stat_period.c
 *
 *  Created on: Oct 29, 2018
 *      Author: nhnghia
 *
 * gcc -g -o stat stat_period.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
 *
 * Usage:
 * ./stat PATH_TO_PCAP_FILE
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

struct stats {
	uint64_t packets;
};

static void _new_ipv4_session_handler(const ipacket_t * ipacket,
		attribute_t * attribute, void * user_args) {

	struct stats *stat = malloc(sizeof(struct stat));
	stat->packets = 0;

	set_user_session_context(ipacket->session, stat);
}

/**
 * Register extraction attributes
 */
static void attributes_iterator(attribute_metadata_t * attribute,
		uint32_t proto_id, void * args) {
	register_extraction_attribute(args, proto_id, attribute->id);
}

/**
 * Interate through all protocol attributes
 */
static void protocols_iterator(uint32_t proto_id, void * args) {
	iterate_through_protocol_attributes(proto_id, attributes_iterator, args);
}

/**
 * Print protocol path into a string
 */
static int proto_hierarchy_ids_to_str(const proto_hierarchy_t * proto_hierarchy,
		char * dest) {
	int offset = 0;
	if (proto_hierarchy->len < 1) {
		offset += sprintf(dest, ".");
	} else {
		int i = 1;
		offset += sprintf(dest, "%s",
				get_protocol_name_by_id(proto_hierarchy->proto_path[i]));
		i++;
		for (; i < proto_hierarchy->len && i < 16; i++) {
			offset += sprintf(&dest[offset], ".%s",
					get_protocol_name_by_id( proto_hierarchy->proto_path[i]));
		}
	}
	return offset;
}

static void _ending_session_handler(const mmt_session_t * dpi_session, void * user_args) {
	struct stats *stat = (struct stats *) get_user_session_context(dpi_session);
	if( stat == NULL )
		return;
	free( stat );
}

static void _session_stat_handler(const mmt_session_t * dpi_session,
		void * user_args) {
	const proto_hierarchy_t *hierarchy = get_session_protocol_hierarchy(
			dpi_session);

	char path[128];
	proto_hierarchy_ids_to_str(hierarchy, path);
	uint64_t ul_packets = get_session_ul_cap_packet_count(dpi_session);
	uint64_t dl_packets = get_session_dl_cap_packet_count(dpi_session);
	uint64_t total_packets = get_session_packet_cap_count(dpi_session);

	uint64_t session_id = get_session_id(dpi_session);

	struct stats *stat = (struct stats *) get_user_session_context(dpi_session);
	if( stat == NULL )
		return;

	//test only on this session
	if (session_id != 1)
		return;

	struct timeval ts = get_session_last_activity_time(dpi_session);

	printf("%lu %s, ul: %3lu, dl: %3lu, tot: %3lu, session_id: %lu, %p, %lu.%06lu\n",
			total_packets - stat->packets,
			path, ul_packets, dl_packets,
			total_packets,

			session_id, dpi_session, ts.tv_sec, ts.tv_usec);

	//remember the total packets of this session
	stat->packets = total_packets;

}

int main(int argc, char ** argv) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s pcap_file\n", argv[0]);
		return EXIT_FAILURE;
	}

	char errbuf[1024];
	mmt_handler_t *mmt_handler; // MMT handler
	pcap_t *pcap; // Pcap handler
	const char *filename = argv[1];

	//Initialize MMT
	init_extraction();

	//Initialize MMT handler
	mmt_handler = mmt_init_handler(DLT_EN10MB, 0, errbuf);
	if (!mmt_handler) {
		fprintf(stderr,
				"[error] MMT handler init failed for the following reason: %s\n",
				errbuf);
		return EXIT_FAILURE;
	}

	//    if (ip_address_classify){
	        printf("Enable classification by IP address");
	        enable_ip_address_classify(mmt_handler);
	//    }else{
	//        disable_ip_address_classify(mmt_handler);
	//    }
	//
	//    if (hostname_classify)
	//    {
	        printf("Enable classification by Hostname");
	        enable_hostname_classify(mmt_handler);
	//    }
	//    else
	//    {
	//        disable_hostname_classify(mmt_handler);
	//    }
	//
	//    if (port_classify)
	//    {
	        printf("Enable classification by Port number\n");
	        enable_port_classify(mmt_handler);
	//    }
	//    else
	//    {
	//        disable_port_classify(mmt_handler);
	//    }
	// Interate throught protocols to register extract all attributes of all protocols
	iterate_through_protocols(protocols_iterator, mmt_handler);

	// Register the callback function when there is a new session has been created
	register_attribute_handler(mmt_handler, PROTO_IP, PROTO_SESSION,
			_new_ipv4_session_handler, NULL, NULL);

	if( !register_session_timeout_handler( mmt_handler, _ending_session_handler, NULL ));

	//	if( !register_session_timeout_handler( mmt_handler, _ending_session_handler, NULL )){
	//		printf( "Cannot register handler for processing a session at ending" );
	//		return EXIT_FAILURE;
	//	}

	if (!register_session_timer_handler(mmt_handler, _session_stat_handler,
			NULL, 1)) {
		printf("Cannot register handler for processing a session at ending");
		return EXIT_FAILURE;
	}

	// OFFLINE mode
	struct pkthdr header; // MMT packet header
	struct pcap_pkthdr p_pkthdr;

	pcap = pcap_open_offline(filename, errbuf);
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

		if (last_ts == 0) //first time
			last_ts = p_pkthdr.ts.tv_sec;
		//do session report each 5 seconds
		else if (p_pkthdr.ts.tv_sec >= last_ts + 5) {
			//push statistic
			process_session_timer_handler(mmt_handler);
			last_ts = p_pkthdr.ts.tv_sec;
		}
	}

	//        process_session_timer_handler( mmt_handler );
	pcap_close( pcap );
	mmt_close_handler( mmt_handler );
	close_extraction();

	return EXIT_SUCCESS;
}
