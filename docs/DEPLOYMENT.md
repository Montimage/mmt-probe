# Deployment Guide

This guide covers deploying MMT-Probe in production environments.

## Installation

### From Source

```bash
git clone https://github.com/montimage/mmt-probe.git
cd mmt-probe
make
sudo make install
```

This installs MMT-Probe to `/opt/mmt/probe` by default.

### From Package

#### Debian/Ubuntu

```bash
make deb
sudo dpkg -i mmt-probe_*.deb
```

#### CentOS/Fedora

```bash
make rpm
sudo rpm -i mmt-probe-*.rpm
```

### Docker

```bash
docker build -t mmt-probe .
docker run --net=host mmt-probe -i eth0
```

## Configuration

The main configuration file is `mmt-probe.conf`. When installed, it is located at `/opt/mmt/probe/mmt-probe.conf`.

Key configuration areas:

- **Input source** -- Network interface or PCAP file
- **Thread count** -- Number of worker threads (`nb-thread`)
- **Output channels** -- File, MQTT, Kafka, Redis, MongoDB, UDP socket
- **Reporting** -- Statistics period, session reports, event reports
- **Security** -- Security rule engine settings
- **Packet capture** -- BPF filters, DPDK ports

See [configuration.md](configuration.md) for all parameters.

## Running as a Service

### Systemd

MMT-Probe includes a systemd service file (installed automatically to the default path):

```bash
# Start the service
sudo systemctl start mmt-probe

# Enable on boot
sudo systemctl enable mmt-probe

# Check status
sudo systemctl status mmt-probe

# View logs
journalctl -u mmt-probe -f
```

### Custom Configuration with Service

Edit `/opt/mmt/probe/mmt-probe.conf` to configure the service, then restart:

```bash
sudo systemctl restart mmt-probe
```

## DPDK Deployment

For high-performance capture using DPDK:

1. Install DPDK and bind NICs to DPDK-compatible drivers
2. Compile MMT-Probe with DPDK support: `make DPDK_CAPTURE compile`
3. Configure hugepages and DPDK EAL parameters

See [dpdk-capture.md](dpdk-capture.md) for detailed DPDK setup.

## Kubernetes

See the Kubernetes deployment guides in [docs/guide/](guide/) for Helm charts and pod configuration.

## Output Integration

### File Output

Reports are written to CSV files in the configured output directory.

### MQTT

Configure `mqtt-output` in `mmt-probe.conf` to publish reports to an MQTT broker.

### Kafka

Configure `kafka-output` in `mmt-probe.conf` or use `kafka.conf` for detailed Kafka producer settings.

### UDP Socket

Configure `socket-output` with type `UDP` for lightweight report forwarding.

## Monitoring

- **Syslog** -- MMT-Probe logs to syslog under the `mmt-probe` tag
- **Packet statistics** -- NIC and MMT drop counters are reported periodically
- **Dynamic configuration** -- Use the UNIX socket interface to query runtime status

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ERROR: Not found MMT-DPI` | Install MMT-DPI or set `MMT_DPI_DIR` / `MMT_BASE` |
| Permission denied on interface | Run with `sudo` or set appropriate capabilities |
| High packet drop rate | Increase `nb-thread`, use DPDK, or apply BPF filters |
| Service won't start | Check `journalctl -u mmt-probe` for errors |
| Configuration parse error | Validate syntax with `./probe -x` to list available attributes |
