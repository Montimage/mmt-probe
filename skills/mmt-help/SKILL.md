---
name: mmt-help
version: 1.0.0
description: General help for MMT-Probe — architecture, protocols, modules, troubleshooting, and ecosystem
---

# MMT-Probe Help

Provide general information about MMT-Probe, its architecture, capabilities, and troubleshooting guidance.

## Triggers

Use this skill when the user asks:
- What is MMT-Probe / what can MMT do
- About the architecture or how it works
- About supported protocols or modules
- For troubleshooting help (errors, crashes, performance)
- About the MMT ecosystem
- General questions not covered by install/configure/operate skills

## What is MMT-Probe

MMT-Probe is a C-based network traffic analysis probe developed by [Montimage](https://www.montimage.com).

- **Repository**: https://github.com/montimage/mmt-probe
- **Version**: 1.6.x
- **License**: Apache License 2.0
- **Language**: C
- **Platforms**: Linux (Ubuntu, Debian, CentOS, Fedora), Docker

### Capabilities

- Deep Packet Inspection (DPI) via MMT-DPI library
- Real-time and offline (PCAP) traffic analysis
- Protocol classification and application identification
- Session-based flow statistics with QoS metrics
- Security rule verification via MMT-Security
- Multi-output: files, Redis, Kafka, MongoDB, MQTT, sockets
- HTTP/FTP data reconstruction
- PCAP packet dumping by protocol
- Custom event and query-based reporting
- Dynamic runtime configuration via Unix socket
- LTE/5G mobile network analysis (eNodeB, GTP, QFI)

## Architecture

MMT-Probe uses a **3-process model**:

```
start =========== monitor proc ================>> end
       |\                            |  |
       | '======= processing proc ==='  |
       |                                |
       '========= control proc ========='
```

1. **Monitor process** (root): Creates and monitors children. Restarts a child if it crashes.
2. **Processing process**: Main packet processing. Reads traffic, performs DPI, generates reports.
3. **Control process** (optional): Listens on a Unix domain socket for runtime control commands. Requires `DYNAMIC_CONFIG_MODULE`.

### Multi-threading

Within the processing process:
- `thread-nb = 0`: Single thread reads and processes packets
- `thread-nb = 1`: One thread reads, one thread processes
- `thread-nb = N`: One reader thread dispatches to N processing threads

Packets are dispatched to threads by flow (same flow always goes to same thread). If a thread's queue is full, the packet is dropped.

## Module System

Modules are selected at compile time via make targets.

| Module | Description | External Dependency |
|--------|-------------|---------------------|
| `QOS_MODULE` | QoS metrics (RTT, response time) | None |
| `REDIS_MODULE` | Redis pub/sub output | hiredis v1.0.2 |
| `KAFKA_MODULE` | Kafka output | librdkafka v1.8.2 |
| `MONGODB_MODULE` | MongoDB output | mongo-c-driver 1.9.5 |
| `MQTT_MODULE` | MQTT output | libpaho-mqtt |
| `SOCKET_MODULE` | Unix/TCP/UDP socket output | None |
| `SECURITY_MODULE` | Security rule verification | MMT-Security + libxml2 |
| `PCAP_DUMP_MODULE` | Dump packets to PCAP files | None |
| `LTE_MODULE` | LTE eNodeB reporting | None |
| `DYNAMIC_CONFIG_MODULE` | Runtime control via Unix socket | None |
| `TCP_REASSEMBLY_MODULE` | TCP segment reassembly | None |
| `HTTP_RECONSTRUCT_MODULE` | Reconstruct HTTP payload | None (implies TCP) |
| `FTP_RECONSTRUCT_MODULE` | Reconstruct FTP files | None (implies TCP) |
| `LICENSE_MODULE` | License key verification | None |
| `NETCONF_MODULE` | NETCONF protocol support | sysrepo + libxml2 (implies DYNAMIC_CONFIG) |

Compile with `ALL_MODULES` to enable everything (all dependencies must be installed).

### Module dependencies

- `HTTP_RECONSTRUCT_MODULE` automatically enables `TCP_REASSEMBLY_MODULE`
- `FTP_RECONSTRUCT_MODULE` automatically enables `TCP_REASSEMBLY_MODULE`
- `TCP_REASSEMBLY_MODULE` requires `enable-tcp-reassembly = true` + `enable-ip-defragmentation = true` in config
- `NETCONF_MODULE` automatically enables `DYNAMIC_CONFIG_MODULE`
- `DPDK_CAPTURE` and `STATIC_LINK` cannot be used together

## Supported Protocols

MMT-Probe identifies protocols via MMT-DPI. Categories include:

### Link Layer
Ethernet, IEEE 802.15.4, Linux cooked capture, ARP, PPP

### Network Layer
IPv4, IPv6, ICMP, ICMPv6, GRE, GTP

### Transport Layer
TCP, UDP, SCTP

### Application Layer
HTTP, HTTPS/SSL/TLS, DNS, FTP, SSH, SMTP, IMAP, POP3, RTP, RTSP, SIP, DHCP, NTP, SNMP, MQTT, CoAP, and 700+ application signatures (Facebook, YouTube, Netflix, etc.)

### Telco/5G
S1AP, NGAP, NAS, GTP-U, GTP-C, PFCP, Diameter, RADIUS

## Quick Reference

### Stack Types

| Value | Protocol |
|-------|----------|
| 1 | Ethernet |
| 624 | Linux cooked capture |
| 800 | IEEE 802.15.4 |

### Report Format IDs

| ID | Report Type |
|----|-------------|
| 1 | Startup (probe version info) |
| 10 | Security alerts |
| 30 | License status |
| 99 | Protocol statistics (non-session) |
| 100 | Session flow statistics |
| 200 | Probe status / liveness |
| 201 | System CPU/memory info |
| 301 | HTTP reconstruction metadata |
| 400 | eNodeB topology events |
| 401 | eNodeB QoS (bearer allocation) |
| 1000 | Custom event reports |

### Output Formats

| Format | Description |
|--------|-------------|
| CSV | Comma-separated, strings in `"`, complex values in `[]` |
| JSON | JSON objects |

### Session Sub-format IDs (within report 100)

| Sub-ID | Protocol | Extra Fields |
|--------|----------|--------------|
| 0 | Default | None |
| 1 | HTTP | Response time, hostname, MIME, URI, method, status |
| 2 | SSL | Server name, CDN flag |
| 3 | RTP | Loss rate, burstiness, jitter, order errors |
| 4 | FTP | Username, password, file info |
| 5 | GTP | Outer IP, TEIDs |

## Troubleshooting Guide

### Compilation Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `ERROR: Not found MMT-DPI at folder /opt/mmt/dpi` | MMT-DPI not installed | Install MMT-DPI first |
| `Not found MMT-Security at /opt/mmt/security` | MMT-Security missing | Install it or remove `SECURITY_MODULE` |
| `-lhiredis` / `-lrdkafka` / `-lmongoc-1.0` not found | Library not installed | Install the library or remove the module |
| Undefined reference errors after module change | Stale object files | Run `make clean` before recompiling |

### Runtime Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `error while loading shared libraries` | Library not in LD path | Run `sudo ldconfig` |
| `Permission denied` on interface | Missing root privileges | Run with `sudo` or set `CAP_NET_RAW` capability |
| Probe exits immediately | License check with no key | Remove `LICENSE_MODULE` or provide `license.key` |
| No config file found | Missing mmt-probe.conf | Use `-c <path>` or place config in `./` or `/opt/mmt/probe/` |

### No Output

1. Check `file-output.enable` is `true`
2. Check `file-output.output-dir` exists and is writable
3. Check `session-report.enable` is `true`
4. For non-file channels, verify the channel is globally enabled
5. For offline mode, verify the PCAP file has traffic matching your config

### Packet Drops

1. Check status reports (ID 200) for `nic-lost` and `mmt-lost` counts
2. Increase `thread-nb` to add processing threads
3. Increase `thread-queue` to buffer more packets per thread
4. Increase `input.buffer-size` for NIC-level buffering
5. Apply BPF filters to reduce packet volume
6. Consider DPDK mode for high-throughput scenarios

### High Memory Usage

1. Reduce `session-timeout` values
2. Reduce `output.cache-max`
3. Enable `micro-flows` to aggregate small flows
4. Disable unused session sub-reports (HTTP, SSL, RTP, FTP, GTP)

## MMT Ecosystem

| Component | Description | Repository |
|-----------|-------------|------------|
| **MMT-DPI** | Deep Packet Inspection library (core dependency) | [montimage/mmt-dpi](https://github.com/montimage/mmt-dpi) |
| **MMT-Probe** | Network traffic analysis probe (this project) | [montimage/mmt-probe](https://github.com/montimage/mmt-probe) |
| **MMT-Security** | Security rule verification engine | [Montimage/mmt-security](https://github.com/Montimage/mmt-security) |
| **MMT-Operator** | Web dashboard for visualization | [montimage/mmt-operator](https://github.com/montimage/mmt-operator) |
| **5Greplay** | 5G traffic replay and testing | [montimage/5greplay](https://github.com/montimage/5greplay) |

### Typical deployment

```
Network Traffic -> MMT-Probe -> [Kafka/Redis/Files] -> MMT-Operator (Web UI)
                      |
                  MMT-Security (rule engine)
```

## Environment Variables

### Build-Time

| Variable | Default | Description |
|----------|---------|-------------|
| `MMT_BASE` | `/opt/mmt` | Base installation directory |
| `MMT_DPI_DIR` | `$MMT_BASE/dpi` | MMT-DPI installation path |
| `MMT_SECURITY_DIR` | `$MMT_BASE/security` | MMT-Security installation path |
| `RTE_SDK` | (unset) | DPDK SDK path |
| `RTE_TARGET` | `build` | DPDK build target |

### System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| OS | Linux (x86_64) | Ubuntu 22.04 |
| RAM | 100 MB | 2 GB+ (DPDK) |
| Disk | ~50 MB | + space for reports |
| Privileges | root or `CAP_NET_RAW` | root |

## Cross-references

- To install MMT-Probe, use `/mmt-install`.
- To configure the probe, use `/mmt-configure`.
- To run and monitor the probe, use `/mmt-operate`.
