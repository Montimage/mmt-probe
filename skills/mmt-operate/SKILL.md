---
name: mmt-operate
version: 1.0.0
description: Run MMT-Probe, understand report output, use dynamic control, and troubleshoot operations
---

# MMT-Probe Operation

Guide the user through running MMT-Probe, interpreting its output, and controlling it at runtime.

## Triggers

Use this skill when the user asks to:
- Run or start MMT-Probe
- Analyze a PCAP file
- Understand report output or data format
- Check probe status or logs
- Control the probe at runtime (start, stop, update)
- Troubleshoot operational issues (no output, packet drops, etc.)

## Execution Modes

### Live capture on interface

```bash
sudo ./probe -i eth0
```

### Offline PCAP analysis

```bash
sudo ./probe -t /path/to/capture.pcap
```

### With a configuration file

```bash
sudo ./probe -c /path/to/mmt-probe.conf
```

### As a systemd service

Available when installed to `/opt/mmt/probe/`.

```bash
sudo systemctl start mmt-probe
sudo systemctl stop mmt-probe
sudo systemctl status mmt-probe
```

### With Docker

```bash
# Live capture
docker run --network=host ghcr.io/montimage/mmt-probe:latest \
    mmt-probe -i eth0 -Xfile-output.enable=true

# PCAP file analysis
docker run -v /path/to/pcaps:/data ghcr.io/montimage/mmt-probe:latest \
    mmt-probe -t /data/capture.pcap
```

### Quick test

```bash
sudo ./probe -t test/UA-Exp01.pcap -Xfile-output.output-dir=/tmp/mmt-test/
ls -la /tmp/mmt-test/
```

## CLI Flags Reference

| Flag | Description | Example |
|------|-------------|---------|
| `-v` | Print version info and exit | `./probe -v` |
| `-h` | Print usage help and exit | `./probe -h` |
| `-c <file>` | Use specific config file | `./probe -c my.conf` |
| `-t <pcap>` | Offline mode: analyze PCAP file | `./probe -t capture.pcap` |
| `-i <iface>` | Online mode: capture on interface | `./probe -i eth0` |
| `-X <key>=<val>` | Override a config parameter | `-Xthread-nb=4` |
| `-x` | List all overridable parameters | `./probe -x` |

Multiple `-X` flags can be combined:

```bash
sudo ./probe -i eth0 -Xfile-output.enable=true -Xsecurity.enable=true -Xthread-nb=2
```

## Report Types

All reports share a common header:

| Column | Name | Description |
|--------|------|-------------|
| 1 | format_id | Report type identifier |
| 2 | probe_id | Probe instance identifier |
| 3 | source | Interface name or PCAP file path |
| 4 | timestamp | Seconds.micros (packet time or real time for id=201) |

### Report Type Summary

| Format ID | Name | Description | Channel |
|-----------|------|-------------|---------|
| 1 | Startup | Sent once at probe start (version info) | — |
| 10 | Security | Security alerts from MMT-Security | `security.report` |
| 30 | License | License status reports | `license.stat` |
| 99 | Protocol Stats | Protocol/app statistics (non-session) | — |
| 100 | Session | Per-flow session statistics | `session.report` |
| 200 | Status | Probe liveness + packet counts (online only) | — |
| 201 | System Info | CPU and memory usage of the host | — |
| 301 | HTTP Reconstruct | Metadata of reconstructed HTTP files | — |
| 400 | eNodeB Topology | LTE element add/remove events | — |
| 401 | eNodeB QoS | UE dedicated bearer allocation | — |
| 1000 | Event | Custom event-triggered reports | `event.report` |

### Status Report (ID 200)

Reports probe liveness during live capture. Created every `stats-period` seconds.

| Col | Name | Description |
|-----|------|-------------|
| 5 | nic-pkt | Packets received by NIC |
| 6 | nic-lost | Packets dropped by NIC |
| 7 | mmt-pkt | Packets received by MMT |
| 8 | mmt-lost | Packets dropped by MMT |
| 9 | mmt-bytes | Bytes received by MMT |
| 10 | mmt-b-lost | Bytes dropped by MMT |

### System Info Report (ID 201)

| Col | Name | Description |
|-----|------|-------------|
| 5 | user_cpu | % CPU in user mode |
| 6 | sys_cpu | % CPU in system mode |
| 7 | idle | % CPU idle |
| 8 | avail_mem | Available memory (kB) |
| 9 | total_mem | Total memory (kB) |

Example: `201,3,"eth0",1498126191.034157,98.57,0.72,0.72,1597680,2048184`

### Session Report (ID 100)

Per-flow statistics with 41 common columns including:
- Client/server IP and MAC addresses (cols 20-23)
- Session ID, ports (cols 24-26)
- Handshake time, app response time, data transfer time (cols 28-30)
- Client/server RTT min/max/avg (cols 31-36)
- TCP retransmissions (cols 37-38)
- Sub-format ID (col 39) determining extension fields

#### Session sub-formats

| Sub-format | Protocol | Extension Fields |
|------------|----------|------------------|
| 0 | Default | (none) |
| 1 | HTTP | Response time, hostname, MIME, referrer, CDN, URI, method, status |
| 2 | SSL | Server name, CDN flag |
| 3 | RTP | Packet loss rate, burstiness, max jitter, order errors |
| 4 | FTP | Username, password, file size, file name, direction |
| 5 | GTP | Outer IP src/dst, TEIDs array |

### Event Report (ID 1000)

| Col | Name | Description |
|-----|------|-------------|
| 5 | event-id | String identifier of the event-report |
| 6 | event | Event attribute value that triggered the report |
| 7+ | attributes | Registered attributes (variable count) |

Example: `1000,3,"./file.pcap",1399407481.189781,1,172.19.190.67,172.19.190.67`

### Security Report (ID 10)

| Col | Name | Description |
|-----|------|-------------|
| 5 | property_id | Rule identifier number |
| 6 | verdict | `detected`, `not_detected`, `respected`, `not_respected`, `unknown` |
| 7 | type | `attack`, `security`, `test`, `evasion` |
| 8 | cause | Description of the property |
| 9 | history | JSON object with events leading to the verdict |

## Output Channel Quick Reference

Reports can be directed to specific output channels using `output-channel`:

```
output-channel = {file}           # File only
output-channel = {redis, kafka}   # Redis and Kafka
output-channel = {file, mongodb, socket, mqtt}  # Multiple
output-channel = {stdout}         # Console output
output-channel = {}               # Default (file)
```

Each channel must be globally enabled (e.g., `kafka-output.enable = true`) for the routing to work.

## Dynamic Control

Requires: `DYNAMIC_CONFIG_MODULE` and `dynamic-config.enable = true`

Control the probe at runtime via Unix domain socket (default: `/tmp/mmt.sock`).

### Start processing

```bash
printf "start\0" | sudo nc -U /tmp/mmt.sock
```

Returns: `0`=success, `1`=already running, `2`=error

### Stop processing

```bash
printf "stop\0" | sudo nc -U /tmp/mmt.sock
```

Returns: `0`=success, `1`=not running, `2`=error

### Update configuration

```bash
printf 'update{\ninput.source="enp0s3"\ninput.mode=ONLINE\n}\0' | sudo nc -U /tmp/mmt.sock
```

Returns: `0`=updated (no restart), `1`=updated (restarted), `2`=syntax error, `3`=internal error

### List parameters

```bash
printf 'ls\0' | sudo nc -U /tmp/mmt.sock
```

## Viewing Logs

```bash
# Systemd service logs
journalctl -t mmt-probe

# Follow logs in real time
journalctl -t mmt-probe -f

# Logs from last hour
journalctl -t mmt-probe --since "1 hour ago"
```

## Performance Tips

1. **Increase threads** for high-throughput: `-Xthread-nb=4`
2. **Increase queue size** to reduce drops: `-Xthread-queue=524288`
3. **Use BPF filters** to reduce processing load: `-Xinput.pcap-filter="tcp port 80"`
4. **Increase cache** for batch efficiency: `-Xoutput.cache-max=500000`
5. **Disable unused reports** to reduce overhead:
   - `-Xsession-report.http=false -Xsession-report.rtp=false`
6. **Use DPDK** for 10Gbps+ links (requires DPDK build)

## Troubleshooting Operations

| Problem | Possible Cause | Solution |
|---------|---------------|----------|
| No output files | `file-output.enable` is false | `-Xfile-output.enable=true` |
| No output files | Wrong output directory | Check `-Xfile-output.output-dir` path exists |
| Probe exits immediately | License check failed | Remove `LICENSE_MODULE` or provide `license.key` |
| High `nic-lost` in status reports | NIC buffer too small | Increase `input.buffer-size` |
| High `mmt-lost` in status reports | Processing too slow | Increase `thread-nb` and `thread-queue` |
| Packet drops with multi-thread | Thread queue full | Increase `thread-queue` value |
| `Permission denied` on interface | Missing root/capabilities | Run with `sudo` or set `CAP_NET_RAW` |
| `error while loading shared libraries` | Library path issue | Run `sudo ldconfig` |
| High memory usage | Too many active sessions | Reduce `session-timeout` values |
| Reports not in expected channel | Channel not enabled | Ensure global `<channel>-output.enable = true` |

## Cross-references

- To install MMT-Probe, use `/mmt-install`.
- To configure the probe, use `/mmt-configure`.
- For general help and architecture, use `/mmt-help`.
