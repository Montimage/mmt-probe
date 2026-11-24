/**
 *
 *  Created on: Mar 16, 2026
 *          by: Huu Nghia
 * xdp_capture.c
 * AF_XDP packet capture input source for mmt-probe.
 *
 * Architecture
 * ─────────────
 *  ┌──────────────┐   XDP prog (BPF)   ┌──────────────┐
 *  │  NIC driver  │ ─────────────────► │  XSK / UMEM  │
 *  └──────────────┘   (pass-all or     └──────┬───────┘
 *                      custom filter)         │  AF_XDP socket
 *                                      ┌──────▼───────┐
 *                                      │ xdp_capture  │  ← this file
 *                                      │   _loop()    │
 *                                      └──────┬───────┘
 *                                             │  xdp_packet_handler_t
 *                                      ┌──────▼───────┐
 *                                      │  mmt-probe   │
 *                                      │  DPI engine  │
 *                                      └──────────────┘
 *
 * Compile:
 *   gcc -O2 -DENABLE_XDP xdp_capture.c -o xdp_capture.o \
 *       -lbpf -lelf -lz
 */

#include "xdp_capture.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>

#include <net/if.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <poll.h>

#include <linux/if_link.h>
#include <linux/if_xdp.h>

#include <bpf/libbpf.h>
#include <bpf/xsk.h>          /* AF_XDP helpers in libbpf >= 0.5 */

/* -------------------------------------------------------------------- */
/* Constants / tunables                                                 */
/* -------------------------------------------------------------------- */

#define XDP_DEFAULT_NUM_FRAMES   4096
#define XDP_DEFAULT_FRAME_SIZE   XSK_UMEM__DEFAULT_FRAME_SIZE   /* 2048 */
#define XDP_DEFAULT_FILL_SIZE    XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XDP_DEFAULT_COMP_SIZE    XSK_RING_CONS__DEFAULT_NUM_DESCS
#define XDP_DEFAULT_RX_RING_SIZE XSK_RING_CONS__DEFAULT_NUM_DESCS
#define XDP_DEFAULT_BATCH_SIZE   64
#define INVALID_UMEM_FRAME       UINT64_MAX

/* -------------------------------------------------------------------- */
/* Internal structures                                                  */
/* -------------------------------------------------------------------- */

/**
 * Simple lock-free stack for tracking free UMEM frames.
 * In a multi-queue design each queue gets its own allocator.
 */
typedef struct {
	uint64_t *frames;
	uint32_t  head;   /* index of next free slot */
	uint32_t  size;
} frame_pool_t;

static inline bool frame_pool_init(frame_pool_t *p, uint32_t n)
{
	p->frames = malloc(n * sizeof(uint64_t));
	if (!p->frames)
		return false;
	p->size = n;
	p->head = 0;
	return true;
}

static inline void frame_pool_push(frame_pool_t *p, uint64_t addr)
{
	p->frames[p->head++] = addr;
}

static inline uint64_t frame_pool_pop(frame_pool_t *p)
{
	if (p->head == 0)
		return INVALID_UMEM_FRAME;
	return p->frames[--p->head];
}

/* -------------------------------------------------------------------- */

struct xdp_capture_context {
	/* --- config copy ---- */
	xdp_capture_config_t cfg;

	/* --- BPF / XDP ------ */
	struct bpf_object   *bpf_obj;   /* loaded BPF object (may be NULL) */
	int                  xdp_prog_fd;
	uint32_t             ifindex;

	/* --- UMEM & socket -- */
	struct xsk_umem     *umem;
	void                *umem_area;
	size_t               umem_size;

	struct xsk_ring_prod fill_ring;
	struct xsk_ring_cons comp_ring;
	struct xsk_ring_cons rx_ring;
	struct xsk_socket   *xsk;
	int                  xsk_fd;

	/* --- frame allocator */
	frame_pool_t         pool;

	/* --- user callback -- */
	xdp_packet_handler_t handler;
	void                *user_data;

	/* --- control -------- */
	volatile atomic_bool running;

	/* --- statistics ----- */
	atomic_uint_least64_t rx_packets;
	atomic_uint_least64_t rx_bytes;
	atomic_uint_least64_t rx_dropped;
	atomic_uint_least64_t rx_invalid;
};

/* -------------------------------------------------------------------- */
/* Forward declarations                                                  */
/* -------------------------------------------------------------------- */

static int  load_xdp_program(xdp_capture_context_t *ctx);
static void unload_xdp_program(xdp_capture_context_t *ctx);
static int  create_umem(xdp_capture_context_t *ctx);
static int  create_xsk(xdp_capture_context_t *ctx);
static void prefill_fill_ring(xdp_capture_context_t *ctx);
static void process_batch(xdp_capture_context_t *ctx);
static void recycle_completions(xdp_capture_context_t *ctx);

/* -------------------------------------------------------------------- */
/* Public API – config                                                   */
/* -------------------------------------------------------------------- */

void xdp_capture_config_init(xdp_capture_config_t *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	cfg->queue_id      = 0;
	cfg->num_frames    = XDP_DEFAULT_NUM_FRAMES;
	cfg->frame_size    = XDP_DEFAULT_FRAME_SIZE;
	cfg->fill_size     = XDP_DEFAULT_FILL_SIZE;
	cfg->comp_size     = XDP_DEFAULT_COMP_SIZE;
	cfg->rx_ring_size  = XDP_DEFAULT_RX_RING_SIZE;
	cfg->batch_size    = XDP_DEFAULT_BATCH_SIZE;
	cfg->zerocopy      = false;      /* safe default; enable if NIC supports */
	cfg->need_wakeup   = true;
	cfg->use_native_xdp= false;      /* SKB fallback – works on all drivers  */
	cfg->bpf_prog_path = NULL;       /* use built-in pass-all prog           */
}

/* -------------------------------------------------------------------- */
/* Public API – open                                                     */
/* -------------------------------------------------------------------- */

xdp_capture_context_t *xdp_capture_open(
		const xdp_capture_config_t *cfg,
		xdp_packet_handler_t        handler,
		void                       *user_data) {
	/* Bump RLIMIT_MEMLOCK so we can lock UMEM pages */
	struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
	if (setrlimit(RLIMIT_MEMLOCK, &rl)) {
		perror("xdp_capture: setrlimit(RLIMIT_MEMLOCK)");
		return NULL;
	}

	if (!cfg || !cfg->interface || !handler) {
		fprintf(stderr, "xdp_capture: invalid arguments\n");
		return NULL;
	}

	xdp_capture_context_t *ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return NULL;

	ctx->cfg       = *cfg;
	ctx->handler   = handler;
	ctx->user_data = user_data;
	atomic_store(&ctx->running, false);

	/* Resolve interface index */
	ctx->ifindex = if_nametoindex(cfg->interface);
	if (!ctx->ifindex) {
		fprintf(stderr, "xdp_capture: unknown interface '%s': %s\n",
				cfg->interface, strerror(errno));
		goto err_free;
	}

	/* Allocate frame pool */
	if (!frame_pool_init(&ctx->pool, cfg->num_frames)) {
		perror("xdp_capture: frame_pool_init");
		goto err_free;
	}

	/* Load (or use built-in) XDP program */
	if (load_xdp_program(ctx) < 0)
		goto err_pool;

	/* Create UMEM */
	if (create_umem(ctx) < 0)
		goto err_xdp;

	/* Create AF_XDP socket */
	if (create_xsk(ctx) < 0)
		goto err_umem;

	/* Pre-populate the FILL ring so the kernel has buffers */
	prefill_fill_ring(ctx);

	fprintf(stderr,
			"xdp_capture: attached to %s (queue %u) ifindex=%u "
			"frames=%u frame_size=%u zerocopy=%d\n",
			cfg->interface, cfg->queue_id, ctx->ifindex,
			cfg->num_frames, cfg->frame_size, (int)cfg->zerocopy);
	return ctx;

	err_umem:
	xsk_umem__delete(ctx->umem);
	munmap(ctx->umem_area, ctx->umem_size);
	err_xdp:
	unload_xdp_program(ctx);
	err_pool:
	free(ctx->pool.frames);
	err_free:
	free(ctx);
	return NULL;
}

/* -------------------------------------------------------------------- */
/* Public API – close                                                    */
/* -------------------------------------------------------------------- */

void xdp_capture_close(xdp_capture_context_t *ctx) {
	if (!ctx)
		return;

	atomic_store(&ctx->running, false);

	if (ctx->xsk)
		xsk_socket__delete(ctx->xsk);

	if (ctx->umem) {
		xsk_umem__delete(ctx->umem);
		munmap(ctx->umem_area, ctx->umem_size);
	}

	unload_xdp_program(ctx);
	free(ctx->pool.frames);
	free(ctx);
}

/* -------------------------------------------------------------------- */
/* Public API – capture loop                                             */
/* -------------------------------------------------------------------- */

int xdp_capture_loop(xdp_capture_context_t *ctx) {
	if (!ctx)
		return -1;

	atomic_store(&ctx->running, true);

	struct pollfd pfd = {
			.fd     = ctx->xsk_fd,
			.events = POLLIN,
	};

	while (atomic_load(&ctx->running)) {
		/* If need_wakeup is set, wake kernel RX path when ring is empty */
		if (ctx->cfg.need_wakeup &&
				xsk_ring_prod__needs_wakeup(&ctx->fill_ring)) {
			recvfrom(ctx->xsk_fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
		}

		int ret = poll(&pfd, 1, 100 /* ms timeout */);
		if (ret < 0) {
			if (errno == EINTR)
				continue;
			perror("xdp_capture: poll");
			atomic_store(&ctx->running, false);
			return -1;
		}

		if (ret == 0)       /* timeout – check running flag */
			continue;

		if (pfd.revents & POLLIN) {
			recycle_completions(ctx);
			process_batch(ctx);
		}
	}

	return 0;
}

void xdp_capture_stop(xdp_capture_context_t *ctx)
{
	if (ctx)
		atomic_store(&ctx->running, false);
}

/* -------------------------------------------------------------------- */
/* Public API – statistics                                               */
/* -------------------------------------------------------------------- */

void xdp_capture_get_stats(
		const xdp_capture_context_t *ctx,
		xdp_capture_stats_t         *stats) {
	if (!ctx || !stats)
		return;
	stats->rx_packets = atomic_load(&ctx->rx_packets);
	stats->rx_bytes   = atomic_load(&ctx->rx_bytes);
	stats->rx_dropped = atomic_load(&ctx->rx_dropped);
	stats->rx_invalid = atomic_load(&ctx->rx_invalid);
}

/* ================================================================== */
/* Internal helpers                                                    */
/* ================================================================== */

/* -------------------------------------------------------------------- */
/* BPF / XDP program management                                         */
/* -------------------------------------------------------------------- */

/*
 * Minimal "pass-everything" XDP program embedded as raw BPF bytecode.
 * Generated from:
 *
 *   SEC("xdp") int xdp_pass(struct xdp_md *ctx) { return XDP_PASS; }
 *
 * This avoids a dependency on an external .o file for the common case.
 * If cfg->bpf_prog_path is set we load that object instead (e.g. for
 * a custom filter that only forwards specific ports to the XSK).
 */
static const struct bpf_insn xdp_pass_prog[] = {
		/* r0 = XDP_PASS (2); exit */
		{ BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, 2 },
		{ BPF_JMP   | BPF_EXIT,         0, 0, 0, 0 },
};

static int load_xdp_program(xdp_capture_context_t *ctx){
	int prog_fd = -1;
	uint32_t xdp_flags = 0;

	if (ctx->cfg.use_native_xdp)
		xdp_flags |= XDP_FLAGS_DRV_MODE;
	else
		xdp_flags |= XDP_FLAGS_SKB_MODE;

	if (ctx->cfg.bpf_prog_path) {
		/* Load user-supplied program */
		struct bpf_prog_load_attr attr = {
				.prog_type = BPF_PROG_TYPE_XDP,
				.file      = ctx->cfg.bpf_prog_path,
		};
		struct bpf_object *obj = NULL;
		if (bpf_prog_load_xattr(&attr, &obj, &prog_fd) < 0) {
			fprintf(stderr, "xdp_capture: failed to load BPF prog '%s': %s\n",
					ctx->cfg.bpf_prog_path, strerror(errno));
			return -1;
		}
		ctx->bpf_obj = obj;
	} else {
		/* Use the built-in pass-all bytecode */
		LIBBPF_OPTS(bpf_prog_load_opts, opts);
		prog_fd = bpf_prog_load(BPF_PROG_TYPE_XDP,
				"xdp_pass",
				"GPL",
				xdp_pass_prog,
				sizeof(xdp_pass_prog) / sizeof(*xdp_pass_prog),
				&opts);
		if (prog_fd < 0) {
			perror("xdp_capture: bpf_prog_load");
			return -1;
		}
	}

	/* Attach to interface */
	if (bpf_set_link_xdp_fd(ctx->ifindex, prog_fd, xdp_flags) < 0) {
		perror("xdp_capture: bpf_set_link_xdp_fd");
		close(prog_fd);
		return -1;
	}

	ctx->xdp_prog_fd = prog_fd;
	return 0;
}

static void unload_xdp_program(xdp_capture_context_t *ctx) {
	if (ctx->ifindex)
		bpf_set_link_xdp_fd(ctx->ifindex, -1, 0);

	if (ctx->xdp_prog_fd > 0) {
		close(ctx->xdp_prog_fd);
		ctx->xdp_prog_fd = -1;
	}

	if (ctx->bpf_obj) {
		bpf_object__close(ctx->bpf_obj);
		ctx->bpf_obj = NULL;
	}
}

/* -------------------------------------------------------------------- */
/* UMEM creation                                                         */
/* -------------------------------------------------------------------- */

static int create_umem(xdp_capture_context_t *ctx) {
	const xdp_capture_config_t *cfg = &ctx->cfg;

	ctx->umem_size = (size_t)cfg->num_frames * cfg->frame_size;
	ctx->umem_area = mmap(NULL, ctx->umem_size,
			PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB,
			-1, 0);
	/* Fall back to regular pages if huge pages unavailable */
	if (ctx->umem_area == MAP_FAILED) {
		ctx->umem_area = mmap(NULL, ctx->umem_size,
				PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	}
	if (ctx->umem_area == MAP_FAILED) {
		perror("xdp_capture: mmap UMEM");
		return -1;
	}

	/* Push all frame addresses onto the free pool */
	for (uint32_t i = 0; i < cfg->num_frames; i++)
		frame_pool_push(&ctx->pool, (uint64_t)i * cfg->frame_size);

	struct xsk_umem_config umem_cfg = {
			.fill_size  = cfg->fill_size,
			.comp_size  = cfg->comp_size,
			.frame_size = cfg->frame_size,
			.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
			.flags      = 0,
	};

	int ret = xsk_umem__create(&ctx->umem, ctx->umem_area, ctx->umem_size,
			&ctx->fill_ring, &ctx->comp_ring,
			&umem_cfg);
	if (ret) {
		fprintf(stderr, "xdp_capture: xsk_umem__create: %s\n",
				strerror(-ret));
		munmap(ctx->umem_area, ctx->umem_size);
		return -1;
	}

	return 0;
}

/* -------------------------------------------------------------------- */
/* AF_XDP socket creation                                                */
/* -------------------------------------------------------------------- */

static int create_xsk(xdp_capture_context_t *ctx) {
	const xdp_capture_config_t *cfg = &ctx->cfg;

	struct xsk_socket_config xsk_cfg = {
			.rx_size           = cfg->rx_ring_size,
			.tx_size           = 0,               /* RX-only */
			.libbpf_flags      = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
			.xdp_flags         = cfg->use_native_xdp ? XDP_FLAGS_DRV_MODE
					: XDP_FLAGS_SKB_MODE,
					  .bind_flags        = (uint16_t)(
							  (cfg->zerocopy    ? XDP_ZEROCOPY  : XDP_COPY) |
							  (cfg->need_wakeup ? XDP_USE_NEED_WAKEUP : 0)
					  ),
	};

	/* NULL TX rings – we are capture-only */
	int ret = xsk_socket__create(&ctx->xsk,
			cfg->interface,
			cfg->queue_id,
			ctx->umem,
			&ctx->rx_ring,
			NULL,  /* tx ring */
			&xsk_cfg);
	if (ret) {
		fprintf(stderr, "xdp_capture: xsk_socket__create: %s\n",
				strerror(-ret));
		return -1;
	}

	ctx->xsk_fd = xsk_socket__fd(ctx->xsk);
	return 0;
}

/* -------------------------------------------------------------------- */
/* Pre-fill the FILL ring with all available UMEM frames                */
/* -------------------------------------------------------------------- */

static void prefill_fill_ring(xdp_capture_context_t *ctx) {
	uint32_t stock = ctx->cfg.fill_size;
	uint32_t idx   = 0;

	uint32_t reserved = xsk_ring_prod__reserve(&ctx->fill_ring, stock, &idx);
	for (uint32_t i = 0; i < reserved; i++) {
		uint64_t addr = frame_pool_pop(&ctx->pool);
		if (addr == INVALID_UMEM_FRAME) {
			/* Fewer frames than fill-ring slots; reserve only what we have */
			xsk_ring_prod__submit(&ctx->fill_ring, i);
			return;
		}
		*xsk_ring_prod__fill_addr(&ctx->fill_ring, idx++) = addr;
	}
	xsk_ring_prod__submit(&ctx->fill_ring, reserved);
}

/* -------------------------------------------------------------------- */
/* Process a batch of received packets                                   */
/* -------------------------------------------------------------------- */

static void process_batch(xdp_capture_context_t *ctx) {
	uint32_t idx_rx = 0;
	uint32_t rcvd   = xsk_ring_cons__peek(&ctx->rx_ring,
			ctx->cfg.batch_size,
			&idx_rx);
	if (!rcvd) {
		atomic_fetch_add(&ctx->rx_dropped, 1);
		return;
	}

	/* We'll reclaim these into the FILL ring after delivery */
	uint32_t idx_fill = 0;
	uint32_t filled   = xsk_ring_prod__reserve(&ctx->fill_ring, rcvd,
			&idx_fill);

	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);

	uint32_t recycled = 0;

	for (uint32_t i = 0; i < rcvd; i++) {
		const struct xdp_desc *desc =
				xsk_ring_cons__rx_desc(&ctx->rx_ring, idx_rx++);

		uint64_t addr   = xsk_umem__add_offset_to_addr(desc->addr);
		uint32_t length = desc->len;
		uint8_t *pkt    = xsk_umem__get_data(ctx->umem_area, addr);

		/* ── dispatch to mmt-probe DPI engine ─────────────────────── */
		ctx->handler(pkt, length, length,
				(uint64_t)ts.tv_sec,
				(uint64_t)(ts.tv_nsec / 1000),
				ctx->user_data);

		atomic_fetch_add(&ctx->rx_packets, 1);
		atomic_fetch_add(&ctx->rx_bytes,   length);

		/* Return the frame to the FILL ring */
		if (recycled < filled) {
			uint64_t recycled_addr = xsk_umem__extract_addr(desc->addr);
			*xsk_ring_prod__fill_addr(&ctx->fill_ring, idx_fill++) =
					recycled_addr;
			recycled++;
		}
	}

	xsk_ring_cons__release(&ctx->rx_ring, rcvd);

	if (recycled)
		xsk_ring_prod__submit(&ctx->fill_ring, recycled);
}

/* -------------------------------------------------------------------- */
/* Recycle TX completions (not used in RX-only mode, kept for symmetry) */
/* -------------------------------------------------------------------- */

static void recycle_completions(xdp_capture_context_t *ctx) {
	uint32_t idx  = 0;
	uint32_t done = xsk_ring_cons__peek(&ctx->comp_ring,
			ctx->cfg.batch_size, &idx);
	if (!done)
		return;

	for (uint32_t i = 0; i < done; i++) {
		uint64_t addr =
				*xsk_ring_cons__comp_addr(&ctx->comp_ring, idx++);
		frame_pool_push(&ctx->pool, xsk_umem__extract_addr(addr));
	}
	xsk_ring_cons__release(&ctx->comp_ring, done);
}
