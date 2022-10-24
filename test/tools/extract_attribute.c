/*
 * extract_attribute.c
 *
 *  Created on: Oct 19, 2018
 *      Author: nhnghia
 *
 * Extract an attribute of a protocol from packets in a pcap file or from NIC
 * Compile this example with:
 *
 * gcc -g -o extract_attribute extract_attribute.c -I /opt/mmt/dpi/include -L /opt/mmt/dpi/lib -lmmt_core -ldl -lpcap
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
#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>

#define MAX_FILENAME_SIZE 256
#define TRACE_FILE 1
#define LIVE_INTERFACE 2
#define MTU_BIG (16 * 1024)

static uint32_t proto_id = PROTO_ETHERNET; //protocol to extract, by default: ethernet
static uint32_t att_id   = ETH_SRC;        //attribute to extract, by default: address source
static uint16_t proto_index = 0;
static uint32_t proto_stack = 1;
/**
 * Packet handler
 * @param ipacket   packet
 * @param user_args user data
 */
int packet_handler(const ipacket_t * ipacket, void * user_args){
	char buffer[255];
	int ret;
	attribute_t *att = NULL;
	if( proto_index == 0 )
		att = get_extracted_attribute( ipacket, proto_id, att_id );
	else
		att = get_extracted_attribute_at_index( ipacket, proto_id, att_id, proto_index );

	if( att == NULL )
		return 0;
	else{
		ret = mmt_attr_sprintf( buffer, sizeof( buffer ), att );
		switch( att->data_type ){
		case MMT_DATA_PATH:
			while( ret < 35 )
				buffer[ret++] = ' ';

			ret = proto_hierarchy_to_str( (proto_hierarchy_t*) att->data, buffer + ret );
			break;
		}
	}
	printf("%6lu    %s\n",  ipacket->packet_id, buffer );

	return 0;
}

void usage(const char * prg_name) {
	fprintf(stderr, "%s [<option>]\n", prg_name);
	fprintf(stderr, "Option:\n");
	fprintf(stderr, "\t-t <trace file>: Gives the trace file to analyse.\n");
	fprintf(stderr, "\t-i <interface> : Gives the interface name for live traffic analysis.\n");
	fprintf(stderr, "\t-p             : ID or Name of protocol to be extracted.\n");
	fprintf(stderr, "\t-a             : ID or Name of attribute to be extracted.\n");
	fprintf(stderr, "\t-d             : Index of protocol to extract. For example: ETH.IP.UDP.GTP.IP, if d=3 (or ignored) IP after ETH, d=6 represent IP after GTP\n");
	fprintf(stderr, "\t-r             : ID of protocol stack. Default = 1 (Ethernet)\n");
	fprintf(stderr, "\t-l             : Print list of protocol and attribute, then exit.\n");
	fprintf(stderr, "\t-h             : Prints this help.\n");
	exit(1);
}

void attributes_iterator(attribute_metadata_t * attribute, uint32_t proto_id, void * args) {
	printf("\t- Attribute id %i, \t Name %s \n", attribute->id, attribute->alias);
}

void protocols_iterator(uint32_t proto_id, void * args) {
	printf("Protocol id %i \t Name %s\n", proto_id, get_protocol_name_by_id(proto_id));
	iterate_through_protocol_attributes(proto_id, attributes_iterator, NULL);
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
	int got_attr_id = 0;
	while ((opt = getopt(argc, argv, "t:i:p:a:d:r:hl")) != EOF) {
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
		case 'p':
			//protocol name
			if( isalpha( optarg[0] )){
				if( got_attr_id ){
					fprintf(stderr, "-p must be set before -a parameters\n");
					exit(1);
				}
				proto_id = get_protocol_id_by_name( optarg );
				if( proto_id == -1){
					fprintf(stderr, "No protocol %s\n", optarg);
					exit(1);
				}
			} else
				proto_id = atol( optarg );
			break;
		case 'a':
			//attribute name
			if( isalpha( optarg[0])) {
				att_id = get_attribute_id_by_protocol_id_and_attribute_name(proto_id, optarg);
				if( att_id == -1 ){
					fprintf(stderr, "No attribute %s of protocol %s\n",
							optarg, get_protocol_name_by_id(proto_id));
					exit( 1 );
				}
				got_attr_id = 1;
			}
			else
				att_id = atol( optarg );
			break;
		case 'd':
			proto_index = atoi( optarg );
			break;
		case 'r':
			proto_stack = atoi( optarg );
			break;
		case 'l':
			//Initialize MMT
			iterate_through_protocols(protocols_iterator, NULL);
			close_extraction();
			exit( 0 );
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

	//Initialize MMT
	init_extraction();

	parseOptions(argc, argv, filename, &type);


	//Initialize MMT handler
	mmt_handler =mmt_init_handler( proto_stack,0,mmt_errbuf);
	if(!mmt_handler){
		fprintf(stderr, "MMT handler init failed for the following reason: %s\n",mmt_errbuf );
		return EXIT_FAILURE;
	}


	//get name of proto_id and att_id
	const char *proto_name = get_protocol_name_by_id( proto_id );
	if( proto_name == NULL ){
		fprintf(stderr, "Not found any protocol using id = %d\n", proto_id );
		return EXIT_FAILURE;
	}
	const char *att_name   = get_attribute_name_by_protocol_and_attribute_ids( proto_id, att_id );
	if( att_name == NULL ){
		fprintf( stderr, "Not found any attribute of %s having id = %d\n", proto_name, att_id );
		return EXIT_FAILURE;
	}


	register_extraction_attribute(mmt_handler,proto_id, att_id);

	register_packet_handler(mmt_handler,1,packet_handler, NULL);

	printf("Packet_id %s.%s\n", proto_name, att_name);
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

	//Close the MMT handler
	mmt_close_handler(mmt_handler);

	//Close MMT
	close_extraction();

	pcap_close(pcap);

	return EXIT_SUCCESS;

}
