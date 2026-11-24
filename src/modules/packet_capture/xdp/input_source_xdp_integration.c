/**
 * input_source.c  (patch / integration sketch)
 * ─────────────────────────────────────────────
 * Shows the minimal changes needed to wire the new XDP capture path
 * into mmt-probe's existing input-source dispatcher alongside the
 * PCAP and DPDK paths already present in the codebase.
 *
 * In the real source tree this logic lives in:
 *   src/modules/packet_capture/  (or similar)
 *
 * Search for the existing switch/if-else on `input.mode` and mirror
 * the DPDK block, replacing dpdk_* calls with xdp_* calls.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>

/* mmt-probe internal headers (paths vary by build) */
#include "mmt_core.h"          /* mmt_handler_t, packet_process_fn     */
#include "packet_capture.h"    /* INPUT_MODE_PCAP / DPDK / XDP, etc.   */
#include "configuration.h"     /* probe_conf_t                         */

/* New XDP header */
#ifdef ENABLE_XDP
#  include "xdp_capture.h"
#endif

/* ------------------------------------------------------------------ */
/* Global stop flag (shared with SIGINT handler)                       */
/* ------------------------------------------------------------------ */
static volatile int g_stop = 0;
static xdp_capture_context_t *g_xdp_ctx = NULL;

static void sig_handler(int sig)
{
    (void)sig;
    g_stop = 1;
#ifdef ENABLE_XDP
    if (g_xdp_ctx)
        xdp_capture_stop(g_xdp_ctx);
#endif
}

/* ------------------------------------------------------------------ */
/* Adapter: translate XDP callback → mmt-probe packet handler          */
/* ------------------------------------------------------------------ */

#ifdef ENABLE_XDP
typedef struct {
    mmt_handler_t *mmt;     /* mmt-probe DPI context */
    /* add per-thread state here if needed */
} xdp_user_ctx_t;

/**
 * Called for every packet received by xdp_capture_loop().
 * This is the bridge between the XDP path and the mmt-dpi engine.
 */
static void xdp_to_mmt_handler(
    const uint8_t *data,
    uint32_t       caplen,
    uint32_t       wirelen,
    uint64_t       ts_sec,
    uint64_t       ts_usec,
    void          *user)
{
    xdp_user_ctx_t *uctx = (xdp_user_ctx_t *)user;

    /* Build the struct that mmt-dpi expects */
    struct pkthdr hdr;
    hdr.ts.tv_sec  = (time_t)ts_sec;
    hdr.ts.tv_usec = (suseconds_t)ts_usec;
    hdr.caplen     = caplen;
    hdr.len        = wirelen;

    /*
     * packet_process() is the existing mmt-probe entry point used by
     * both the PCAP and DPDK capture paths.  Calling it here means
     * the XDP path reuses the entire DPI/security/output pipeline
     * without any further changes.
     */
    packet_process(uctx->mmt, &hdr, data);
}
#endif /* ENABLE_XDP */

/* ------------------------------------------------------------------ */
/* Main dispatcher – extend the existing input-mode switch             */
/* ------------------------------------------------------------------ */

/**
 * start_capture() is called by mmt-probe's main() after configuration
 * is parsed.  Extend the existing switch to handle INPUT_MODE_XDP.
 *
 * Suggested addition to mmt-probe.conf:
 *
 *   input {
 *       mode   = XDP              # new mode value
 *       source = "eth0"           # interface name
 *       # XDP-specific (all optional – defaults shown):
 *       xdp-queue        = 0
 *       xdp-num-frames   = 4096
 *       xdp-frame-size   = 2048
 *       xdp-batch-size   = 64
 *       xdp-zerocopy     = false
 *       xdp-native       = false  # true = DRV mode (faster, NIC-dependent)
 *       xdp-bpf-prog     = ""     # path to custom .o; empty = pass-all
 *   }
 */
int start_capture(probe_conf_t *conf, mmt_handler_t *mmt)
{
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    switch (conf->input.mode) {

    /* ---- existing PCAP path (unchanged) ------------------------- */
    case INPUT_MODE_PCAP:
        return start_pcap_capture(conf, mmt);  /* existing function */

    /* ---- existing DPDK path (unchanged) ------------------------- */
#ifdef ENABLE_DPDK
    case INPUT_MODE_DPDK:
        return start_dpdk_capture(conf, mmt);  /* existing function */
#endif

    /* ---- new XDP path ------------------------------------------ */
#ifdef ENABLE_XDP
    case INPUT_MODE_XDP: {
        xdp_capture_config_t xdp_cfg;
        xdp_capture_config_init(&xdp_cfg);

        /* Map probe_conf_t fields → xdp_capture_config_t */
        xdp_cfg.interface     = conf->input.source;
        xdp_cfg.queue_id      = (uint32_t)conf->input.xdp_queue;
        xdp_cfg.num_frames    = conf->input.xdp_num_frames
                                    ? conf->input.xdp_num_frames : 4096;
        xdp_cfg.batch_size    = conf->input.xdp_batch_size
                                    ? conf->input.xdp_batch_size : 64;
        xdp_cfg.zerocopy      = conf->input.xdp_zerocopy;
        xdp_cfg.use_native_xdp= conf->input.xdp_native;
        xdp_cfg.bpf_prog_path = conf->input.xdp_bpf_prog[0]
                                    ? conf->input.xdp_bpf_prog : NULL;

        xdp_user_ctx_t uctx = { .mmt = mmt };

        g_xdp_ctx = xdp_capture_open(&xdp_cfg, xdp_to_mmt_handler, &uctx);
        if (!g_xdp_ctx) {
            fprintf(stderr, "start_capture: xdp_capture_open failed\n");
            return -1;
        }

        int ret = xdp_capture_loop(g_xdp_ctx);

        /* Print final stats */
        xdp_capture_stats_t stats;
        xdp_capture_get_stats(g_xdp_ctx, &stats);
        fprintf(stderr,
                "XDP capture stats: rx_packets=%llu rx_bytes=%llu "
                "dropped=%llu invalid=%llu\n",
                (unsigned long long)stats.rx_packets,
                (unsigned long long)stats.rx_bytes,
                (unsigned long long)stats.rx_dropped,
                (unsigned long long)stats.rx_invalid);

        xdp_capture_close(g_xdp_ctx);
        g_xdp_ctx = NULL;
        return ret;
    }
#endif /* ENABLE_XDP */

    default:
        fprintf(stderr, "start_capture: unknown input mode %d\n",
                conf->input.mode);
        return -1;
    }
}
