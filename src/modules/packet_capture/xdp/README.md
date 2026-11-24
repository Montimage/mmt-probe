======================================================================
XDP Capture Extension for mmt-probe
README / Build Instructions
======================================================================
# Overview
--------
These files add an AF_XDP (eXpress Data Path) packet capture path to
mmt-probe alongside the existing PCAP and DPDK inputs.
#  File                            Purpose
 ──────────────────────────────  ─────────────────────────────────────
 xdp_capture.h                   Public API (open / loop / close / stats)
 xdp_capture.c                   User-space AF_XDP implementation
 xdp_prog_kern.c                 Kernel BPF/XDP program (pass-all +
                                 optional port filter)
 input_source_xdp_integration.c  Glue showing how to hook the new
                                 path into mmt-probe's input dispatcher
# Why XDP?
--------
 • Kernel-bypass for RX: packets are DMA'd straight from the NIC into
   a user-space memory region (UMEM) with no copy through the socket
   buffer or pcap ring.
 • Dramatically lower CPU overhead and latency than libpcap at high
   packet rates (10 Gbps+).
 • Works on standard Linux with any NIC that has a kernel driver
   (SKB/generic mode) – no proprietary firmware or huge-page pools
   required (unlike DPDK).
 • Full kernel TCP/IP stack remains intact on the same interface when
   using the port-filter BPF program, so management connectivity is
   preserved.
# Performance expectations
------------------------
 Mode              Typical throughput (64-byte frames, single core)
 ─────────────────────────────────────────────────────────────────
 libpcap (TPACKET_V3)          ~2–4 Mpps
 AF_XDP  SKB/generic mode      ~4–7 Mpps
 AF_XDP  native DRV mode       ~10–20 Mpps  (NIC driver support needed)
 AF_XDP  zero-copy mode        ~20–40 Mpps  (NIC + driver support needed)
# Prerequisites
-------------
  sudo apt install libbpf-dev linux-headers-$(uname -r) \
                   clang llvm gcc make libelf-dev zlib1g-dev
#   # Optional – xdp-tools for xdp-loader and libxdp
  git clone https://github.com/xdp-project/xdp-tools
  cd xdp-tools && ./configure && make && sudo make install
# Building the kernel BPF program
--------------------------------
  clang -O2 -g -Wall -target bpf \
        -I/usr/include/$(uname -m)-linux-gnu \
        -c xdp_prog_kern.c -o xdp_prog_kern.o
# Building mmt-probe with XDP support
------------------------------------
Add to the existing Makefile (or CMakeLists.txt):

LAGS  += -DENABLE_XDP
FLAGS += -lbpf -lelf -lz

Add the new source file:
SOURCES += src/modules/packet_capture/xdp_capture.c

Quick smoke-test (requires root or CAP_NET_ADMIN + CAP_BPF):
------------------------------------------------------------
  sudo ./mmt-probe -i eth0 -m XDP
  # or via config:
  sudo ./mmt-probe -c mmt-probe.conf  # with input.mode = XDP

mmt-probe.conf snippet
----------------------
#   input {
      mode             = XDP
      source           = "eth0"         # interface name
#       # XDP tuning (all optional)
      xdp-queue        = 0              # RX queue index
      xdp-num-frames   = 4096           # UMEM frame count (power of 2)
      xdp-frame-size   = 2048           # bytes per frame  (2048 or 4096)
      xdp-batch-size   = 64             # packets per poll iteration
      xdp-zerocopy     = false          # true if NIC supports it
      xdp-native       = false          # true = DRV mode (faster)
      xdp-bpf-prog     = ""             # path to .o; empty = pass-all
  }
# Multi-queue capture
-------------------
For line-rate capture on multi-queue NICs, run one mmt-probe instance
per RX queue (or use RSS to steer all flows to queue 0):
#   for q in 0 1 2 3; do
    sudo ./mmt-probe -c probe_q${q}.conf &   # each conf: xdp-queue = $q
  done
# Alternatively, set NIC RSS to one queue before starting:
  sudo ethtool -L eth0 combined 1
# Capabilities (avoiding full root)
----------------------------------
  sudo setcap cap_net_admin,cap_bpf,cap_net_raw+ep ./mmt-probe
# Kernel version notes
--------------------
  >= 4.18   AF_XDP introduced (copy mode only)
  >= 5.4    AF_XDP stable; XDP_USE_NEED_WAKEUP added
  >= 5.10   Recommended minimum; zero-copy support mature in mlx5/i40e
  >= 5.19   bpf_redirect_map() reliable for XSK maps in SKB mode
# Troubleshooting
---------------
  ENOTSUP on xsk_socket__create  → NIC does not support native XDP;
    set xdp-native = false (SKB/generic mode) or update the driver.
#   ENOMEM on mmap UMEM           → reduce xdp-num-frames or increase
    RLIMIT_MEMLOCK.
#   Zero packets received         → check BPF program is attached:
    sudo bpftool net show dev eth0
    sudo ip link show eth0        (look for "xdp" tag)
#   High drop rate                → increase xdp-num-frames and
    xdp-fill-size; or reduce batch latency by lowering xdp-batch-size.
