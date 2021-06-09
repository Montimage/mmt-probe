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

static uint32_t print_delay = 1; // default number of package between each print
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

#define PKTMBUF_POOL_NAME "MProc_pktmbuf_pool"
#define PKT_READ_SIZE ((uint16_t)32)
#define LOCAL_EXPERIMENTAL_ETHER 0x88B5
#define DEFAULT_PKT_NUM 128
#define MAX_PKT_NUM NF_QUEUE_RINGSIZE
#define DEFAULT_NUM_CHILDREN 0
static uint16_t num_children = DEFAULT_NUM_CHILDREN;
static uint8_t use_shared_core_allocation = 0;
static uint8_t d_addr_bytes[RTE_ETHER_ADDR_LEN];
static uint16_t packet_size = RTE_ETHER_HDR_LEN;
static uint32_t packet_number = DEFAULT_PKT_NUM;

/* For advanced rings scaling */
rte_atomic16_t signal_exit_flag;
uint8_t ONVM_NF_SHARE_CORES;
struct child_spawn_info {
    struct onvm_nf_init_cfg *child_cfg;
    struct onvm_nf *parent;
};

/*
 * Print a usage message.
 */
static void
usage(const char* progname) {
    printf("Usage:\n");
    printf(
        "%s [EAL args] -- [NF_LIB args] -- -d <destination> [-p <print_delay>] "
        " \n", progname);
    printf("%s -F <CONFIG_FILE.json> [EAL args] -- [NF_LIB args] -- [NF args]\n\n", progname);
    printf("Flags:\n");
    printf(" - `-d DST`: Destination Service ID to foward to\n");
    printf(" - `-p PRINT_DELAY`: Number of packets between each print, e.g. `-p 1` prints every packets.\n");
}

/*
 * Parse the ONVM arguments.
 */
static int
parse_app_args(int argc, char *argv[]) {
    int c, dst_flag = 0;
    while ((c = getopt(argc, argv, "d:p:n:")) != -1) {
        switch (c) {
            case 'd':
                destination = strtoul(optarg, NULL, 10);
                dst_flag = 1;
                break;
            case 'p':
                print_delay = strtoul(optarg, NULL, 10);
                break;
            case 'n':
                num_children = strtoul(optarg, NULL, 10);
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
 * Gets IP source of each packet.
 */
static void
get_ip_source(struct rte_mbuf *pkt) {
    struct rte_ipv4_hdr *ip = onvm_pkt_ipv4_hdr(pkt);
    char ip_string[16];
    if (ip != NULL) {
        //onvm_pkt_print(pkt);
        onvm_pkt_parse_char_ip(ip_string, rte_be_to_cpu_32(ip->src_addr));
        printf("Process packet from IP source %s\n", ip_string);
    } else {
        printf("No IP4 header found\n");
    }
}

/*
 * Checks whether packets are HTTP or not.
 */
int
http_packet_handler(const ipacket_t *ipacket, void *user_args) {
    unsigned int http_index = get_protocol_index_by_id(ipacket, PROTO_HTTP);
    if (http_index == -1) {
        DEBUG("not HTTP packet: %lu", ipacket->packet_id);
    } else {
        DEBUG("HTTP packet: %lu", ipacket->packet_id);
        nb_http_pkts++;
    }
    return 0;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf *pkt) {
    const char clr[] = {27, '[', '2', 'J', '\0'};
    const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0'};

    /* Clear screen and move to top left */
    printf("%s%s", clr, topLeft);

    DEBUG("PACKETS");
    DEBUG("-----");
    DEBUG("Port : %d", pkt->port);
    DEBUG("Size : %d", pkt->pkt_len);
    DEBUG("N°   : %" PRIu64 "", total_packets);
    DEBUG("");
}

void
nf_setup(__attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    uint32_t i;
    struct rte_mempool *pktmbuf_pool;

    pktmbuf_pool = rte_mempool_lookup(PKTMBUF_POOL_NAME);
    if (pktmbuf_pool == NULL) {
        onvm_nflib_stop(nf_local_ctx);
        rte_exit(EXIT_FAILURE, "Cannot find mbuf pool!\n");
    }

    for (i = 0; i < packet_number; ++i) {
        struct onvm_pkt_meta *pmeta;
        struct rte_ether_hdr *ehdr;
        int j;

        struct rte_mbuf *pkt = rte_pktmbuf_alloc(pktmbuf_pool);
        if (pkt == NULL)
            break;

        /* set up ether header and set new packet size */
        ehdr = (struct rte_ether_hdr *)rte_pktmbuf_append(pkt, packet_size);

        /* Using manager mac addr for source*/
        if (onvm_get_macaddr(0, &ehdr->s_addr) == -1) {
            onvm_get_fake_macaddr(&ehdr->s_addr);
        }
        for (j = 0; j < RTE_ETHER_ADDR_LEN; ++j) {
            ehdr->d_addr.addr_bytes[j] = d_addr_bytes[j];
        }
        ehdr->ether_type = LOCAL_EXPERIMENTAL_ETHER;

        pmeta = onvm_get_pkt_meta(pkt);
        pmeta->destination = destination;
        pmeta->action = ONVM_NF_ACTION_TONF;
        pkt->hash.rss = i;
        pkt->port = 0;

        onvm_nflib_return_pkt(nf_local_ctx->nf, pkt);
    }
}

/*
 * Processes each incoming packet.
 */
static int
packet_handler(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
    __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    static uint32_t counter = 0;
    static uint64_t pkt_process = 0;
    const u_char *pkt_data;
    struct timespec time_now __rte_cache_aligned;
    struct pkthdr pkt_header __rte_cache_aligned;

    total_packets++;
    pkt_header.len = pkt->pkt_len;
    pkt_header.caplen = pkt-> data_len;
    if (onvm_mode) {
        clock_gettime(CLOCK_REALTIME_COARSE, &time_now);
        pkt_header.ts.tv_sec = time_now.tv_sec;
        pkt_header.ts.tv_usec = time_now.tv_nsec / 1000;
        DEBUG("Time : %ld.%ld", time_now.tv_sec, time_now.tv_nsec / 1000);
    } else {
        pkt_header.ts.tv_sec = pkt->timestamp / US_PER_S;
        pkt_header.ts.tv_usec = pkt->timestamp % US_PER_S;
        DEBUG("Time : %ld.%ld", pkt->timestamp / US_PER_S, pkt->timestamp % US_PER_S);
    }
    pkt_data = (pkt->buf_addr + pkt->data_off);
    if (!packet_process(dpi_handler, &pkt_header, pkt_data)) {
        nb_not_processed++;
        rte_exit(EXIT_FAILURE, "Packet process failed\n");
    }

    if (counter++ == print_delay) {
        do_stats_display(pkt);
        counter = 0;
    }

    meta->destination = destination;
    meta->action = ONVM_NF_ACTION_TONF;

    cur_time = time(NULL);
    // send reports periodically
    if(cur_time >= next_stat_ts){
        next_stat_ts += stat_period;
        dpi_callback_on_stat_period(dpi_context);
        /*output_flush(output);*/
    }
    output_flush(output);

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
        dpi_callback_on_stat_period(dpi_context);
        output_flush(output);
    }
    output_flush(output);

    return 0;
}

void sig_handler(int sig) {
    if (sig != SIGINT && sig != SIGTERM)
        return;

    /* Will stop the processing for all spawned threads in advanced rings mode */
    rte_atomic16_set(&signal_exit_flag, 1);
}

/*
 * Basic packet handler, just forwards all packets to destination
 */
static int
packet_handler_fwd(struct rte_mbuf *pkt, struct onvm_pkt_meta *meta,
                   __attribute__((unused)) struct onvm_nf_local_ctx *nf_local_ctx) {
    (void)pkt;
    meta->destination = destination;
    meta->action = ONVM_NF_ACTION_TONF;

    return 0;
}

void *
start_child(void *arg) {
    struct onvm_nf_local_ctx *child_local_ctx;
    struct onvm_nf_init_cfg *child_init_cfg;
    struct onvm_nf *parent;
    struct child_spawn_info *spawn_info;

    spawn_info = (struct child_spawn_info *)arg;
    child_init_cfg = spawn_info->child_cfg;
    parent = spawn_info->parent;
    child_local_ctx = onvm_nflib_init_nf_local_ctx();

    if (onvm_nflib_start_nf(child_local_ctx, child_init_cfg) < 0) {
        printf("Failed to spawn child NF\n");
        return NULL;
    }

    /* Keep track of parent for proper termination */
    child_local_ctx->nf->thread_info.parent = parent->instance_id;

    thread_main_loop(child_local_ctx);
    onvm_nflib_stop(child_local_ctx);
    free(spawn_info);
    return NULL;
}

int
thread_main_loop(struct onvm_nf_local_ctx *nf_local_ctx) {
    void *pkts[PKT_READ_SIZE];
    struct onvm_pkt_meta *meta;
    uint16_t i, nb_pkts;
    struct rte_mbuf *pktsTX[PKT_READ_SIZE];
    int tx_batch_size;
    struct rte_ring *rx_ring;
    struct rte_ring *msg_q;
    struct onvm_nf *nf;
    struct onvm_nf_msg *msg;
    struct rte_mempool *nf_msg_pool;

    nf = nf_local_ctx->nf;

    onvm_nflib_nf_ready(nf);
    /*nf_setup(nf_local_ctx);*/

    /* Get rings from nflib */
    rx_ring = nf->rx_q;
    msg_q = nf->msg_q;
    nf_msg_pool = rte_mempool_lookup(_NF_MSG_POOL_NAME);

    printf("Process %d handling packets using advanced rings\n", nf->instance_id);
    if (onvm_threading_core_affinitize(nf->thread_info.core) < 0)
            rte_exit(EXIT_FAILURE, "Failed to affinitize to core %d\n", nf->thread_info.core);

    while (!rte_atomic16_read(&signal_exit_flag)) {
        /* Check for a stop message from the manager */
        if (unlikely(rte_ring_count(msg_q) > 0)) {
            msg = NULL;
            rte_ring_dequeue(msg_q, (void **)(&msg));
            if (msg->msg_type == MSG_STOP) {
                rte_atomic16_set(&signal_exit_flag, 1);
            } else {
                printf("Received message %d, ignoring", msg->msg_type);
            }
            rte_mempool_put(nf_msg_pool, (void *)msg);
        }

        tx_batch_size = 0;
        /* Dequeue all packets in ring up to max possible */
        nb_pkts = rte_ring_dequeue_burst(rx_ring, pkts, PKT_READ_SIZE, NULL);

        if (unlikely(nb_pkts == 0)) {
            if (ONVM_NF_SHARE_CORES) {
                rte_atomic16_set(nf->shared_core.sleep_state, 1);
                sem_wait(nf->shared_core.nf_mutex);
            }
            continue;
        }
        /* Process all the packets */
        for (i = 0; i < nb_pkts; i++) {
            meta = onvm_get_pkt_meta((struct rte_mbuf *)pkts[i]);
            packet_handler_fwd((struct rte_mbuf *)pkts[i], meta, nf_local_ctx);
            pktsTX[tx_batch_size++] = pkts[i];
        }
        /* Process all packet actions */
        onvm_pkt_process_tx_batch(nf->nf_tx_mgr, pktsTX, tx_batch_size, nf);
        if (tx_batch_size < PACKET_READ_SIZE) {
            onvm_pkt_flush_all_nfs(nf->nf_tx_mgr, nf);
        }
    }
    return 0;
}

/*
 * Initalize onvm local context.
 */
struct onvm_nf_local_ctx*
onvm_capture_init(probe_context_t *context) {
    char *onvm_argv[100];
	int onvm_argc = string_split(context->config->input->onvm_options, " ", &onvm_argv[1], 100-1);
    int arg_offset, i;

    struct onvm_nf_local_ctx *nf_local_ctx;
    struct onvm_nf_function_table *nf_function_table;

    nf_local_ctx = onvm_nflib_init_nf_local_ctx();
    /* If we're using advanced rings also pass a custom cleanup function,
     * this can be used to handle NF specific (non onvm) cleanup logic */
    rte_atomic16_init(&signal_exit_flag);
    rte_atomic16_set(&signal_exit_flag, 0);
    onvm_nflib_start_signal_handler(nf_local_ctx, sig_handler);
    /* No need to define a function table as adv rings won't run onvm_nflib_run */
    nf_function_table = NULL;

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

    /*nf_local_ctx = onvm_nflib_init_nf_local_ctx();*/
    /*onvm_nflib_start_signal_handler(nf_local_ctx, NULL);*/

    /*nf_function_table = onvm_nflib_init_nf_function_table();*/
    /*nf_function_table->pkt_handler = &packet_handler;*/
    /*nf_function_table->user_actions = &callback_handler;*/

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

    pthread_t nf_thread[num_children];
    struct onvm_configuration *onvm_config;
    struct onvm_nf *nf;
    nf = nf_local_ctx->nf;
    onvm_config = onvm_nflib_get_onvm_config();
    ONVM_NF_SHARE_CORES = onvm_config->flags.ONVM_NF_SHARE_CORES;

    for (i = 0; i < num_children; i++) {
        struct onvm_nf_init_cfg *child_cfg;
        child_cfg = onvm_nflib_init_nf_init_cfg(nf->tag);
        /* Prepare init data for the child */
        child_cfg->service_id = nf->service_id;
        struct child_spawn_info *child_data = malloc(sizeof(struct child_spawn_info));
        child_data->child_cfg = child_cfg;
        child_data->parent = nf;
        /* Increment the children count so that stats are displayed and NF does proper cleanup */
        rte_atomic16_inc(&nf->thread_info.children_cnt);
        pthread_create(&nf_thread[i], NULL, start_child, (void *)child_data);
    }

    thread_main_loop(nf_local_ctx);
    onvm_nflib_stop(nf_local_ctx);

    for (i = 0; i < num_children; i++) {
        pthread_join(nf_thread[i], NULL);
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

    if(output)
        _send_version_information(output);

    /*onvm_nflib_run(nf_local_ctx);*/
}

/*
 * Stop NF Probe.
 */
void
onvm_capture_stop(struct onvm_nf_local_ctx *nf_local_ctx) {
    onvm_nflib_stop(nf_local_ctx);

    mmt_close_handler(dpi_handler);
    dpi_release(dpi_context);

    printf("Total packets received: %" PRIu64 " \n", total_packets);
    printf("Total HTTP packets received: %" PRIu64 " \n", nb_http_pkts);
    printf("Total packets not being processed: %" PRIu64 " \n", nb_not_processed);
}
