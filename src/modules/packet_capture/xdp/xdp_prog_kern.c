// SPDX-License-Identifier: GPL-2.0
/**
 *
 *  Created on: Mar 16, 2026
 *          by: Huu Nghia
 *
 * xdp_prog_kern.c
 * Kernel-side BPF/XDP program for mmt-probe's AF_XDP capture path.
 *
 * Two programs are provided:
 *
 *  1. xdp_pass_all  – redirect every packet to the AF_XDP socket.
 *     Use this as a drop-in default.
 *
 *  2. xdp_redirect_port_filter – steer only packets matching
 *     a configurable set of TCP/UDP destination ports to the XSK,
 *     and let the rest pass through the normal kernel network stack
 *     (XDP_PASS).  This avoids disrupting management traffic
 *     (SSH, etc.) on a shared interface.
 *
 * Build:
 *   clang -O2 -g -Wall -target bpf \
 *         -I/usr/include/$(uname -m)-linux-gnu \
 *         -c xdp_prog_kern.c -o xdp_prog_kern.o
 *
 * The resulting .o file can be passed to mmt-probe via:
 *   input { bpf-prog = "/path/to/xdp_prog_kern.o"; }
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/* ------------------------------------------------------------------ */
/* Maps                                                                */
/* ------------------------------------------------------------------ */

/**
 * xsks_map  – one entry per NIC RX queue, filled by user-space
 * (xsk_socket__update_xskmap from libbpf) so the BPF program can
 * redirect packets to the correct AF_XDP socket.
 */
struct {
	__uint(type,        BPF_MAP_TYPE_XSKMAP);
	__uint(max_entries, 64);           /* support up to 64 queues */
	__uint(key_size,    sizeof(__u32));
	__uint(value_size,  sizeof(__u32));
} xsks_map SEC(".maps");

/**
 * port_filter_map  – hash map of __be16 destination ports that
 *  should be steered to the XSK.  Empty → steer everything.
 *  Populated by user-space at startup (or dynamically updated).
 *
 *  Key:   __be16 port number (network byte order)
 *  Value: __u8   1 = redirect, 0 = pass
 */
struct {
	__uint(type,        BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__uint(key_size,    sizeof(__u16));
	__uint(value_size,  sizeof(__u8));
} port_filter_map SEC(".maps");

/**
 * stats_map  – per-CPU counters so user-space can read capture stats
 * without taking a lock.
 */
struct xdp_stats {
	__u64 rx_redirected;
	__u64 rx_passed;
	__u64 rx_aborted;
};

struct {
	__uint(type,        BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(key_size,    sizeof(__u32));
	__uint(value_size,  sizeof(struct xdp_stats));
} stats_map SEC(".maps");

/* ------------------------------------------------------------------ */
/* Helper: redirect to the AF_XDP socket of the current RX queue      */
/* ------------------------------------------------------------------ */

static __always_inline int redirect_to_xsk(struct xdp_md *ctx)
{
	__u32 key  = 0;  /* use index 0 for stats */
	__u32 zero = 0;

	struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);
	int rc = bpf_redirect_map(&xsks_map, ctx->rx_queue_index, XDP_PASS);

	if (stats) {
		if (rc == XDP_REDIRECT)
			stats->rx_redirected++;
		else
			stats->rx_passed++;
		(void)key;
	}
	return rc;
}

/* ------------------------------------------------------------------ */
/* Program 1: pass-all (default)                                       */
/* ------------------------------------------------------------------ */

SEC("xdp")
int xdp_pass_all(struct xdp_md *ctx)
{
	return redirect_to_xsk(ctx);
}

/* ------------------------------------------------------------------ */
/* Program 2: port-filtered redirect                                   */
/* ------------------------------------------------------------------ */

/**
 * Parse Ethernet/IP/IPv6 and return the TCP or UDP *destination* port,
 * or 0 if the packet is neither TCP nor UDP.
 */
static __always_inline __u16 parse_dst_port(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;

	/* Ethernet header */
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return 0;

	__u16 eth_type = bpf_ntohs(eth->h_proto);
	__u8  ip_proto = 0;
	void *l4       = NULL;

	if (eth_type == ETH_P_IP) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return 0;
		/* Reject fragmented packets (offset != 0) */
		if (ip->frag_off & bpf_htons(IP_MF | IP_OFFSET))
			return 0;
		ip_proto = ip->protocol;
		l4       = (void *)ip + (ip->ihl * 4);
	} else if (eth_type == ETH_P_IPV6) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return 0;
		ip_proto = ip6->nexthdr;
		l4       = (void *)(ip6 + 1);
	} else {
		return 0;  /* non-IP: let kernel handle it */
	}

	if (ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcp = l4;
		if ((void *)(tcp + 1) > data_end)
			return 0;
		return bpf_ntohs(tcp->dest);
	}

	if (ip_proto == IPPROTO_UDP) {
		struct udphdr *udp = l4;
		if ((void *)(udp + 1) > data_end)
			return 0;
		return bpf_ntohs(udp->dest);
	}

	return 0;
}

SEC("xdp")
int xdp_redirect_port_filter(struct xdp_md *ctx)
{
	__u32 zero  = 0;
	struct xdp_stats *stats = bpf_map_lookup_elem(&stats_map, &zero);

	/* Check if the port filter map is empty (no entries pinned yet).
	 * When map is empty we redirect everything, matching pass-all behaviour. */
	__u16 dst_port = parse_dst_port(ctx);
	if (dst_port == 0) {
		/* Non-TCP/UDP → redirect anyway so mmt-probe sees all traffic */
		return redirect_to_xsk(ctx);
	}

	__u16 key   = (__u16)dst_port;
	__u8 *match = bpf_map_lookup_elem(&port_filter_map, &key);

	if (!match || *match == 1) {
		/* Port is in the filter map (or map is empty) → redirect to XSK */
		return redirect_to_xsk(ctx);
	}

	/* Port explicitly excluded → pass to normal kernel stack */
	if (stats)
		stats->rx_passed++;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
