#ifndef ONVM
#define ONVM
#endif

#include <onvm_nflib.h>
#include <onvm_pkt_helper.h>

#include <mmt_core.h>
#include <tcpip/mmt_tcpip.h>
#include "../output/output.h"
#include "../dpi/dpi.h"
#include "../../worker.h"

#define NF_TAG "probe"

static uint32_t print_delay = 10000000; // number of package between each print
static uint32_t destination;
static uint8_t onvm_mode = 1; // default online mode
const char* progname = "mmt-probe";

static uint64_t total_packets = 0;
static uint64_t nb_http_pkts = 0;
static uint64_t nb_not_processed = 0;
static uint32_t stat_period = 0; // period of sampling in seconds
time_t next_stat_ts = 0; // moment we need to do statistic
time_t next_output_ts = 0; // moment we need flush output to channels
time_t cur_time; // current timestamp

mmt_handler_t *dpi_handler;
dpi_context_t *dpi_context;
output_t *output;

/*
 * Print a usage message.
 */
static void
usage(const char* progname) {
    printf("Usage:\n");
    printf(
        "%s [EAL args] -- [NF_LIB args] -- -d <destination> [-p <print_delay>] "
        "[-m <onvm_mode>] \n",
        progname);
    printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
    printf("Flags:\n");
    printf(" - `-d DST`: Destination Service ID to foward to\n");
    printf(" - `-p PRINT_DELAY`: Number of packets between each print, e.g. `-p 1` prints every packets.\n");
    printf(" - `-m MODE`: ONVM capture mode, e.g. `-m 1` captures online, `-m 0` replays pcap files.\n");
}

/*
 * Parse the ONVM arguments.
 */
static int
parse_app_args(int argc, char *argv[]) {
    int c, dst_flag = 0;
    while ((c = getopt(argc, argv, "d:p")) != -1) {
        switch (c) {
            case 'd':
                destination = strtoul(optarg, NULL, 10);
                dst_flag = 1;
                break;
            case 'p':
                print_delay = strtoul(optarg, NULL, 10);
                break;
            default:
                usage(progname);
                return -1;
        }
    }
    if (!dst_flag) {
        return -1;
    }
    return 0;
}

/*
 * Checks whether packets are HTTP or not.
 */
int
http_packet_handler(const ipacket_t *ipacket, void *user_args) {
    unsigned int http_index = get_protocol_index_by_id(ipacket, PROTO_HTTP);
    if (http_index == -1) {
        printf("[debug] not HTTP packet: %lu\n", ipacket->packet_id);
    } else {
        printf("[debug] HTTP packet: %lu\n", ipacket->packet_id);
        nb_http_pkts++;
    }
    return 0;
}

/*
 * Processes each incoming packet.
 */
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
    /*Clear screen and move to top left*/
    printf("%s%s", clr, topLeft);

    static uint32_t counter = 0;
    static uint64_t pkt_process = 0;
    struct rte_ipv4_hdr *ip;
    const u_char *pkt_data;
    struct pkthdr pkt_header __rte_cache_aligned;
    struct timespec time_now __rte_cache_aligned;

    clock_gettime( CLOCK_REALTIME_COARSE, &time_now );
    total_packets++;
    pkt_header.len = pkt->pkt_len;
    pkt_header.caplen = pkt-> data_len;
    pkt_header.ts.tv_sec = time_now.tv_sec;
    pkt_header.ts.tv_usec = time_now.tv_nsec / 1000;
    //_uint64_to_timeval(&pkt_header.ts, pkt->udata64 );
    pkt_data = (pkt->buf_addr + pkt->data_off);
    if (!packet_process(dpi_handler, &pkt_header, pkt_data)) {
        rte_exit(EXIT_FAILURE, "Packet process failed\n");
    }

    printf("PACKETS\n");
    printf("-----\n");
    printf("Port : %d\n", pkt->port);
    printf("Size : %d\n", pkt->pkt_len);
    printf("N°   : %" PRIu64 "\n", total_packets);
    printf("Time : %ld.%ld\n", time_now.tv_sec, time_now.tv_nsec / 1000);
    printf("\n");

    ip = onvm_pkt_ipv4_hdr(pkt);
    char ip_string[16];
    if (ip != NULL) {
        //onvm_pkt_print(pkt);
        onvm_pkt_parse_char_ip(ip_string, rte_be_to_cpu_32(ip->src_addr));
        printf("Process packet from IP source %s\n", ip_string);
    } else {
        printf("No IP4 header found\n");
    }

    printf("Total HTTP packets received: %" PRIu64 " \n", nb_http_pkts);
    printf("Total packets received: %" PRIu64 " \n", total_packets);

    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = destination;
    return 0;
}

/*
 * Processes each packet from the pcap file.
 */
static int
pcap_packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};
    /*Clear screen and move to top left*/
    printf("%s%s", clr, topLeft);

    static uint64_t pkt_process = 0;
    struct rte_ipv4_hdr *ip;
    struct pkthdr header;
    const u_char *pkt_data;
    struct pkthdr pkt_header __rte_cache_aligned;

    total_packets++;
    pkt_header.len = pkt->pkt_len;
    pkt_header.caplen = pkt-> data_len;
    pkt_header.ts.tv_sec = pkt->timestamp / US_PER_S;
    pkt_header.ts.tv_usec = pkt->timestamp % US_PER_S;
    pkt_data = (pkt->buf_addr + pkt->data_off);
    if (!packet_process(dpi_handler, &pkt_header, pkt_data)) {
        nb_not_processed++;
        rte_exit(EXIT_FAILURE, "Packet process failed\n");
    }

    printf("PACKETS\n");
    printf("-----\n");
    printf("Size : %d\n", pkt->pkt_len);
    printf("N°   : %" PRIu64 "\n", total_packets);
    printf("Time : %ld.%ld\n", pkt_header.ts.tv_sec, pkt_header.ts.tv_usec);
    printf("Timestamp   : %" PRIu64 "\n", pkt->timestamp);
    printf("\n");

    ip = onvm_pkt_ipv4_hdr(pkt);
    char ip_string[16];
    if (ip != NULL) {
        //onvm_pkt_print(pkt);
        onvm_pkt_parse_char_ip(ip_string, rte_be_to_cpu_32(ip->src_addr));
        printf("Process packet from IP source %s\n", ip_string);
    } else {
        printf("No IP4 header found\n");
    }

    printf("Total HTTP packets received: %" PRIu64 " \n", nb_http_pkts);
    printf("Total packets not being processed: %" PRIu64 " \n", nb_not_processed);
    printf("Total packets received: %" PRIu64 " \n", total_packets);

    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = destination;
    return 0;
}

/*
 * Generates reports each "start_period" seconds.
 */
static int
callback_handler(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    cur_time = time(NULL);
    // send reports periodically
    if(cur_time >= next_stat_ts){
        next_stat_ts += stat_period;
        /*printf("callback_handler now   : %ld\n", cur_time);*/
        /*printf("callback_handler next_start_ts   : %ld\n", next_stat_ts);*/
        dpi_callback_on_stat_period(dpi_context);
        output_flush(output);
    }
    output_flush(output);

    return 0;
}

/*
 * Initalize onvm local context.
 */
struct onvm_nf_local_ctx*
onvm_capture_init(probe_context_t *context) {
    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;
    char *onvm_argv[100];
	int onvm_argc = string_split(context->config->input->onvm_options, " ", &onvm_argv[1], 100-1);
    int arg_offset, i;

    stat_period = context->config->stat_period;
    onvm_mode = context->config->input->onvm_mode;
    printf("stat_period: %d, onvm_mode: %d\n", stat_period, onvm_mode);

    // the first parameter is normally program name "mmt-probe"
	onvm_argv[0] = LOG_IDENT;
	onvm_argc   += 1;
    printf("onvm_argc: %d\n", onvm_argc);
    for(i = 0; i < onvm_argc; ++i) {
        printf("%s ", onvm_argv[i]);
    }

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    onvm_nflib_start_signal_handler(nf_local_ctx, NULL);

    nf_function_table = onvm_nflib_init_nf_function_table();
    // call corresponding packet_handler() depending on the onvm capture mode (1: online; 0: pcap)
    if (onvm_mode)
        nf_function_table->pkt_handler = &packet_handler;
    else
        nf_function_table->pkt_handler = &pcap_packet_handler;
    nf_function_table->user_actions = &callback_handler;

    if ((arg_offset = onvm_nflib_init(onvm_argc, onvm_argv, NF_TAG, nf_local_ctx, nf_function_table)) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        if (arg_offset == ONVM_SIGNAL_TERMINATION) {
            printf("Exiting due to user termination\n");
            return 0;
        } else {
            rte_exit(EXIT_FAILURE, "Failed ONVM init\n");
        }
    }

    // parse onvm arguments
    onvm_argc -= arg_offset;
    if (parse_app_args(onvm_argc, &onvm_argv[arg_offset]) < 0) {
        onvm_nflib_stop(nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
    }

    return nf_local_ctx;
}

/*
 * Start capturing packets.
 */
void
onvm_capture_start(probe_context_t *context, struct onvm_nf_local_ctx *nf_local_ctx) {
    cur_time = time(NULL);
    next_stat_ts = cur_time + stat_period;

    // initialize MMT handler
    char errbuf[1024];
    dpi_handler = mmt_init_handler(1, 0, errbuf);
    if(dpi_handler){
	    printf("MMT handler init OK\n");
    }
    // also check HTTP/non-HTTP packets
    register_packet_handler(dpi_handler, 1, http_packet_handler, NULL);

    probe_conf_t *config = context->config;
    output = output_alloc_init(1,
			&(config->outputs),
			config->probe_id,
			config->input->input_source,

			//when enable security, we need to synchronize output as it can be called from
			//- worker thread, or,
			//- security threads
#ifdef SECURITY_MODULE
			(config->reports.security->is_enable
			&& config->reports.security->threads_size != 0)
#else
			false
#endif
	);
    if(output){
	    printf("Output init OK\n");
    }

    dpi_context = dpi_alloc_init(config, dpi_handler, output, 0);
    if(dpi_context){
	    printf("DPI context init OK\n");
    }

    /*if(output)*/
		/*_send_version_information(output);*/

    onvm_nflib_run(nf_local_ctx);
}

/*
 * Stop NF Probe.
 */
void
onvm_capture_stop(struct onvm_nf_local_ctx *nf_local_ctx) {
    onvm_nflib_stop(nf_local_ctx);

    mmt_close_handler(dpi_handler);
    dpi_release(dpi_context);
}
