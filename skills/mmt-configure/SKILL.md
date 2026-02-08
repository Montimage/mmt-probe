---
name: mmt-configure
version: 1.0.0
description: Configure MMT-Probe input, output channels, reports, security, and performance tuning
---

# MMT-Probe Configuration

Guide the user through configuring MMT-Probe for their specific use case.

## Triggers

Use this skill when the user asks to:
- Configure MMT-Probe or edit mmt-probe.conf
- Set up input source (interface, PCAP file)
- Enable or configure output channels (file, Redis, Kafka, MongoDB, MQTT, socket)
- Configure reports (session, event, security, query)
- Tune performance (threads, queues, timeouts)
- Override configuration at runtime

## Important: Docker / Non-root Environments

Inside Docker containers you typically run as root, so `sudo` is not needed and may not be available. **Omit `sudo` from all commands when running inside Docker.** All commands below show `sudo` for host use; drop it in containers.

## Configuration Basics

MMT-Probe uses **libconfuse** format for its configuration file.

### Config file search order

1. Path given via `-c <path>` CLI option
2. `./mmt-probe.conf` in the current working directory
3. `/opt/mmt/probe/mmt-probe.conf` (installed default)

If no config file is found, the probe stops.

### Runtime override with `-X`

Any configuration parameter can be overridden at runtime:

```bash
./probe -i eth0 -Xfile-output.enable=true -Xfile-output.output-dir=/tmp/
```

### List all overridable parameters

```bash
./probe -x
```

## Global Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `probe-id` | int | `3` | Unique identifier for this probe instance |
| `stack-type` | int | `1` | Root protocol stack: `1`=Ethernet, `800`=IEEE 802.15.4, `624`=Linux cooked |
| `stack-offset` | int | `0` | Byte offset into the packet |
| `license` | string | `"./license.key"` | Path to license key file |
| `enable-proto-without-session-report` | bool | `false` | Report non-IP traffic (ARP, PPP) |
| `enable-ip-fragmentation-report` | bool | `false` | Report IP fragmentation info |
| `enable-ip-defragmentation` | bool | `false` | Perform IP defragmentation |
| `enable-tcp-reassembly` | bool | `false` | Reassemble TCP segments (requires ip-defrag) |
| `enable-report-version-info` | bool | `true` | Print probe version to output channels |
| `stats-period` | int | `5` | Statistics sampling period in seconds |

## Input Configuration

```
input {
    mode = ONLINE            # ONLINE (live) or OFFLINE (pcap file)
    source = "eth0"          # Interface name or PCAP file path
    snap-len = 0             # Max packet size (0 = 65535 default)
    buffer-size = 4096       # PCAP buffer size in bytes
    timeout = 1000           # PCAP buffer timeout in milliseconds
    dpdk-option = ""         # DPDK EAL options (DPDK mode only)
    pcap-filter = ""         # BPF filter (PCAP mode only)
}
```

### BPF filter examples

| Filter | Description |
|--------|-------------|
| `"tcp port 80"` | TCP traffic on port 80 |
| `"udp port 53"` | DNS queries |
| `"host 192.168.1.1"` | All traffic to/from a host |
| `"src net 192.168.0.0/16"` | Packets from a subnet |
| `"tcp and not port 22"` | TCP excluding SSH |

### DPDK multi-port input

In DPDK mode, use comma-separated port numbers: `source = "0,1"`. Traffic is aggregated across ports.

## Output Format and Cache

```
output {
    format = CSV             # CSV or JSON
    cache-max = 100000       # Max messages in cache before flush
    cache-period = 5         # Flush interval in seconds
}
```

The cache is flushed when full OR when `cache-period` elapses. For file output with `sample-file=true`, a new file is created each `cache-period` seconds.

## Output Channels

### File Output

```
file-output {
    enable = true
    output-file = "data.csv"
    output-dir = "/opt/mmt/probe/result/report/online"
    sample-file = true       # Create new file each cache-period
    retain-files = 80        # Keep last N files (0 = keep all)
}
```

> `retain-files` must be greater than `thread-nb + 1`.

### Redis Output

Requires: `REDIS_MODULE` + hiredis v1.0.2

```
redis-output {
    enable = true
    hostname = "localhost"
    port = 6379
    channel = "report"       # Redis pub/sub channel name
}
```

### Kafka Output

Requires: `KAFKA_MODULE` + librdkafka v1.8.2

```
kafka-output {
    enable = true
    hostname = "localhost"
    port = 9092
    topic = "report"         # Kafka topic name
}
```

### MongoDB Output

Requires: `MONGODB_MODULE` + mongo-c-driver 1.9.5

```
mongodb-output {
    enable = true
    hostname = "localhost"
    port = 27017
    database = "mmt-data"
    collection = "reports"
    limit-size = 0           # Max collection size in MB (0 = unlimited)
}
```

When `limit-size` is set, oldest reports are removed to maintain the limit.

### MQTT Output

Requires: `MQTT_MODULE` + libpaho-mqtt

```
mqtt-output {
    enable = true
    address = "tcp://localhost:1883"   # protocol://host:port
    topic = "report"
    retain = false
}
```

Supported protocols: `tcp://`, `mqtt://`, `ssl://`, `mqtts://`, `ws://`, `wss://`

### Socket Output

Requires: `SOCKET_MODULE`

```
socket-output {
    enable = true
    type = BOTH              # UNIX, TCP, UDP, or BOTH (UNIX+TCP)
    descriptor = "/tmp/mmt-probe-output.sock"  # UNIX socket path
    hostname = "127.0.0.1"   # TCP/UDP host
    port = 5000              # TCP/UDP port
}
```

## Report Configuration

### Session Report (format ID 100)

```
session-report {
    enable = true
    output-channel = {file}  # {file, redis, kafka, mongodb, socket, mqtt}
    ftp = false
    http = true
    rtp = false
    ssl = true
    gtp = false
    rtt-base = CAPTOR        # CAPTOR, SENDER, or PREFER_SENDER
}
```

### Event Report (format ID 1000)

Custom event-triggered reports. Name must be unique.

```
event-report my-events {
    enable = true
    event = "ip.src"
    attributes = {"ip.src", "ip.dst", "meta.proto_hierarchy"}
    output-channel = {file}
}
```

With custom output format (replaces `attributes`):

```
event-report ip-json {
    enable = true
    event = "ip.src"
    output-format = '{"source": "ip.src", "destination": "ip.dst"}'
    output-channel = {socket, stdout}
}
```

With delta condition (report only on change):

```
event-report int {
    enable = true
    event = "int.latency"
    delta-cond = {"int.num_hop", "int.hop_switch_ids"}
    attributes = {"ip.src", "ip.dst", "int.num_hop", "int.hop_latencies"}
    output-channel = {}
}
```

### Query Report

SQL-like aggregation over packet streams.

```
query-report avg-udp {
    enable = true
    ms-period = 33           # Report interval in milliseconds
    output-channel = {socket}
    select = {"last(ip.src)", "avg(meta.packet_len)", "count(meta.packet_index)"}
    where = {"udp.len"}      # Only process UDP packets
    group-by = {"ip.src", "ip.dst"}
}
```

Supported operators: `sum`, `count`, `avg`, `var`, `diff`, `last`, `first`

### Security Report (format ID 10)

Requires: `SECURITY_MODULE`

```
security {
    enable = true
    thread-nb = 1
    exclude-rules = ""
    rules-mask = ""          # e.g., "(1:1,2,4-6)(2:3)"
    output-channel = {file}
    report-rule-description = true
    ignore-remain-flow = true
    input.max-message-size = 60000
    security.max-instances = 100000
    security.smp.ring-size = 1000
    ip-encapsulation-index = LAST  # FIRST, LAST, or N
}
```

### System Report (format ID 201)

```
system-report {
    enable = true
    period = 5               # Reporting period in seconds
    output-channel = {}
}
```

## Performance Tuning

### Threading

```
thread-nb = 0                # 0=single thread, 1+=multi-thread
thread-queue = 262144        # Max packets queued per thread
```

- `thread-nb = 0`: one thread reads and processes packets
- `thread-nb = 1`: one thread reads, another processes
- `thread-nb = N`: one reader thread, N processing threads

If a thread's queue is full, incoming packets are dropped.

### Session Timeouts

```
session-timeout {
    default-session-timeout = 60
    short-session-timeout = 15
    long-session-timeout = 6000    # Web/SSL with long polling
    live-session-timeout = 1500    # Persistent connections
}
```

## Advanced Features

### Dynamic Configuration

Requires: `DYNAMIC_CONFIG_MODULE`

```
dynamic-config {
    enable = true
    descriptor = "/tmp/mmt.sock"
}
```

Allows runtime control via Unix socket. See `/mmt-operate` for commands.

### PCAP Dump

Requires: `PCAP_DUMP_MODULE`

```
dump-pcap {
    enable = true
    output-dir = "/opt/mmt/probe/pcaps/"
    protocols = {"unknown"}  # Protocols to dump
    period = 60              # New file every N seconds
    retain-files = 50
    snap-len = 65355
}
```

### Data Reconstruction

Requires: `enable-tcp-reassembly = true` and `enable-ip-defragmentation = true`

```
reconstruct-data http {
    enable = true
    output-dir = "/tmp/"
    output-channel = {}
}

reconstruct-data ftp {
    enable = true
    output-dir = "/tmp/"
    output-channel = {}
}
```

### Micro-flows

Aggregate small flows by protocol ID to reduce report volume.

```
micro-flows {
    enable = true
    packet-threshold = 2
    byte-threshold = 100
    report-packet-count = 1000
    report-byte-count = 10000
    report-flow-count = 500
    output-channel = {}
}
```

## Common Configuration Recipes

### High-throughput monitoring

```bash
./probe -i eth0 \
  -Xthread-nb=4 \
  -Xthread-queue=524288 \
  -Xoutput.cache-max=500000 \
  -Xsession-report.enable=true \
  -Xfile-output.enable=true \
  -Xfile-output.output-dir=/data/mmt/
```

### Security analysis

```bash
./probe -i eth0 \
  -Xsecurity.enable=true \
  -Xsecurity.thread-nb=2 \
  -Xsession-report.ssl=true \
  -Xfile-output.enable=true
```

### Kafka streaming pipeline

```bash
./probe -i eth0 \
  -Xkafka-output.enable=true \
  -Xkafka-output.hostname=kafka-broker \
  -Xkafka-output.port=9092 \
  -Xkafka-output.topic=mmt-reports \
  -Xsession-report.output-channel={kafka}
```

### Offline forensic analysis

```bash
./probe -t /path/to/capture.pcap \
  -Xfile-output.enable=true \
  -Xfile-output.output-dir=/tmp/analysis/ \
  -Xsession-report.http=true \
  -Xsession-report.ssl=true \
  -Xsession-report.ftp=true
```

## Cross-references

- To install MMT-Probe and its dependencies, use `/mmt-install`.
- To run the probe and understand output, use `/mmt-operate`.
- For general help and troubleshooting, use `/mmt-help`.
