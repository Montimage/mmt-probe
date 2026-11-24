/**
 *
 *  Created on: Mar 16, 2026
 *          by: Huu Nghia
 *
 * xdp_capture.h
 * XDP-based packet capture input source for mmt-probe.
 *
 * Drop-in alongside the existing pcap_capture / dpdk_capture sources.
 * Packets are received via AF_XDP sockets (XSKs) and handed to
 * mmt-probe's existing packet-processing pipeline through the same
 * callback interface used by the PCAP input.
 *
 * Requirements:
 *   - Linux kernel >= 5.4  (AF_XDP stable)
 *   - libbpf  >= 0.5       (sudo apt install libbpf-dev)
 *   - libxdp  >= 1.2       (from xdp-tools; optional, improves portability)
 *   - Kernel headers        (sudo apt install linux-headers-$(uname -r))
 *
 * Build flag: -DENABLE_XDP  (add to Makefile when libbpf is present)
 */

#ifndef XDP_CAPTURE_H
#define XDP_CAPTURE_H

#include <stdint.h>
#include <stdbool.h>

/* ---------- public types -------------------------------------------- */

/**
 * Opaque handle returned by xdp_capture_open().
 * Callers should treat this as an abstract "input source".
 */
typedef struct xdp_capture_context xdp_capture_context_t;

/**
 * Per-packet callback – identical signature to mmt-probe's existing
 * pcap_packet_handler so the same processing path can be reused.
 *
 * @param data      pointer to the first byte of the Ethernet frame
 * @param caplen    number of bytes actually available
 * @param wirelen   original wire length (may be larger than caplen)
 * @param ts_sec    capture timestamp – seconds part
 * @param ts_usec   capture timestamp – microseconds part
 * @param user      opaque pointer supplied to xdp_capture_open()
 */
typedef void (*xdp_packet_handler_t)(
    const uint8_t *data,
    uint32_t       caplen,
    uint32_t       wirelen,
    uint64_t       ts_sec,
    uint64_t       ts_usec,
    void          *user
);

/**
 * Configuration block – mirrors the `input {}` section of mmt-probe.conf.
 */
typedef struct xdp_capture_config {
    const char *interface;       /**< e.g. "eth0"                          */
    uint32_t    queue_id;        /**< NIC RX queue to attach to (0-based)  */
    uint32_t    num_frames;      /**< XDP UMEM frame count (power of 2)    */
    uint32_t    frame_size;      /**< frame size in bytes  (2048 or 4096)  */
    uint32_t    fill_size;       /**< FILL ring size       (power of 2)    */
    uint32_t    comp_size;       /**< COMPLETION ring size (power of 2)    */
    uint32_t    rx_ring_size;    /**< RX ring size         (power of 2)    */
    uint32_t    batch_size;      /**< packets dequeued per poll iteration  */
    bool        zerocopy;        /**< request XDP_ZEROCOPY flag            */
    bool        need_wakeup;     /**< use XDP_USE_NEED_WAKEUP flag         */
    bool        use_native_xdp;  /**< XDP_FLAGS_DRV_MODE vs SKB fallback   */
    const char *bpf_prog_path;   /**< optional: path to custom .o BPF prog */
} xdp_capture_config_t;

/* ---------- life-cycle ---------------------------------------------- */

/**
 * Initialise an AF_XDP socket on the requested interface/queue,
 * load a minimal (pass-all) XDP program, and return a context handle.
 *
 * Returns NULL on error; errno is set and an error message is printed
 * to stderr.
 */
xdp_capture_context_t *xdp_capture_open(
    const xdp_capture_config_t *cfg,
    xdp_packet_handler_t        handler,
    void                       *user_data
);

/**
 * Detach the XDP program, close the AF_XDP socket, and free all
 * resources associated with ctx.  Safe to call with ctx == NULL.
 */
void xdp_capture_close(xdp_capture_context_t *ctx);

/* ---------- capture loop -------------------------------------------- */

/**
 * Block and dispatch packets until xdp_capture_stop() is called from
 * another thread (or a signal fires).  Returns 0 on clean stop, -1 on
 * fatal error.
 *
 * This mirrors pcap_capture_loop() / dpdk_capture_loop() so that
 * mmt-probe's main thread can call one generic function pointer.
 */
int xdp_capture_loop(xdp_capture_context_t *ctx);

/**
 * Signal xdp_capture_loop() to return.  Safe to call from a signal
 * handler or a different thread.
 */
void xdp_capture_stop(xdp_capture_context_t *ctx);

/* ---------- statistics ---------------------------------------------- */

typedef struct xdp_capture_stats {
    uint64_t rx_packets;   /**< packets received and dispatched           */
    uint64_t rx_bytes;     /**< total bytes received                      */
    uint64_t rx_dropped;   /**< packets dropped (ring full / no umem buf) */
    uint64_t rx_invalid;   /**< frames rejected by the BPF program        */
} xdp_capture_stats_t;

/** Populate *stats from the current context.  Thread-safe. */
void xdp_capture_get_stats(
    const xdp_capture_context_t *ctx,
    xdp_capture_stats_t         *stats
);

/* ---------- helper: default config ---------------------------------- */

/** Fill *cfg with sane defaults; caller overrides as needed. */
void xdp_capture_config_init(xdp_capture_config_t *cfg);

#endif /* XDP_CAPTURE_H */
