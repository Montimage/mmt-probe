# DPDK Packet Capture

MMT-Probe supports [DPDK](https://www.dpdk.org/) as a high-performance alternative to libpcap for packet capture. DPDK bypasses the kernel network stack to achieve near line-rate packet processing.

## Prerequisites

- DPDK installed and configured on the system
- NICs bound to a DPDK-compatible driver (e.g., `vfio-pci`, `igb_uio`)
- Hugepages configured
- `RTE_SDK` and `RTE_TARGET` environment variables set

## Compilation

```bash
# Set DPDK environment variables
export RTE_SDK=/path/to/dpdk
export RTE_TARGET=x86_64-native-linuxapp-gcc

# Compile MMT-Probe with DPDK support
make DPDK_CAPTURE compile
```

> **Note:** `DPDK_CAPTURE` and `STATIC_LINK` cannot be used together.

## Configuration

When compiled with DPDK, configure the input source using DPDK port numbers instead of interface names:

```
input {
    mode = ONLINE
    source = "0"         # DPDK port 0
}
```

For multi-port capture, specify comma-separated port numbers:

```
input {
    mode = ONLINE
    source = "0,1"       # DPDK ports 0 and 1
}
```

## Performance Reference

### Max Throughput vs. Packet Size

Packet size in bytes (excluding CRC):

| Max throughput |   60  |   64  |  128  |  256  |  512  |  750  |  1024  |  1250  |  1514  |
|----------------|------:|------:|------:|------:|------:|------:|-------:|-------:|-------:|
|   Gbps         |  7.14 |  7.27 |  8.42 |  9.14 |  9.55 |  9.69 |  9.77  |  9.81  |  9.84  |
|   Mpps         | 14.88 | 14.21 |  8.22 |  4.46 |  2.33 |  1.62 |  1.19  |  0.98  |  0.82  |

### Timestamping Accuracy

DPDK uses CPU cycle counters (`rte_rdtsc`) for timestamping. Accuracy depends on CPU frequency stability and whether TSC is invariant.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `EAL: No available hugepages` | Configure hugepages: `echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages` |
| `EAL: Cannot open PCI device` | Bind NIC to DPDK driver: `dpdk-devbind.py --bind=vfio-pci <pci-address>` |
| DPDK init fails silently | Check `RTE_SDK` and `RTE_TARGET` environment variables are correctly set |
| Probe exits on init error | MMT-Probe exits cleanly on DPDK errors so the monitor process does not restart in a loop |

## See Also

- [Installation Guide](installation.md) -- Build options and module compilation
- [Architecture](architecture.md) -- Process model and module system
- [DPDK Documentation](https://doc.dpdk.org/guides/)
