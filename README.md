# MMT-Probe

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![GitHub Issues](https://img.shields.io/github/issues/montimage/mmt-probe)](https://github.com/montimage/mmt-probe/issues)
[![GitHub Stars](https://img.shields.io/github/stars/montimage/mmt-probe)](https://github.com/montimage/mmt-probe/stargazers)
![](https://komarev.com/ghpvc/?username=montimage-probe&style=flat-square&label=Page+Views)

**MMT-Probe** is a high-performance network traffic analysis tool that performs deep and light packet inspection on live or captured network traffic. It is part of the [Montimage Monitoring Tool (MMT)](https://montimage.com) suite.

## Key Features

- **Deep Packet Inspection (DPI)** -- Detailed protocol analysis using the MMT-DPI library
- **Light Packet Inspection (LPI)** -- Fast packet analysis for high-volume scenarios (e.g., DDoS detection)
- **Session & Event Reporting** -- Aggregated statistics per network session and configurable event-based reports
- **Security Analysis** -- Integrated security rule engine for real-time threat detection (via MMT-Security)
- **Multiple Input Modes** -- Live interface capture (libpcap or DPDK) and offline PCAP file analysis
- **Flexible Output** -- Reports to files, MQTT, Kafka, Redis, MongoDB, or UDP sockets
- **Dynamic Reconfiguration** -- Modify parameters at runtime via UNIX domain sockets
- **IPv4/IPv6 Support** -- Including IP fragmentation and TCP reassembly
- **Docker Support** -- Ready-to-use container image

## Quick Start

### Prerequisites

- GCC 4.9+ and build tools
- [MMT-DPI](https://github.com/montimage/mmt-dpi) installed
- libconfuse (`sudo apt-get install libconfuse-dev`)

### Build & Run

```bash
git clone https://github.com/montimage/mmt-probe.git
cd mmt-probe
make
sudo make install

# Analyze a PCAP file
sudo ./probe -t /path/to/capture.pcap

# Capture live traffic
sudo ./probe -i eth0
```

See the full [Installation Guide](./docs/installation.md) for optional modules (DPDK, Kafka, MQTT, Security, etc.).

## Usage

```
./probe [<option>]
Options:
   -v               : Print version information, then exit
   -c <config file> : Path to configuration file (default: ./mmt-probe.conf)
   -t <trace file>  : Trace file for offline analysis
   -i <interface>   : Interface name for live traffic analysis
   -X attr=value    : Override configuration attributes
   -x               : Print list of overridable configuration attributes, then exit
   -h               : Print help, then exit
```

## Project Structure

```
mmt-probe/
├── src/
│   ├── main.c                 # Entry point
│   ├── configure.c/h          # Configuration parsing
│   ├── worker.c/h             # Worker thread management
│   ├── lib/                   # Utility libraries
│   └── modules/               # Feature modules
│       ├── dpi/               # Deep packet inspection
│       ├── lpi/               # Light packet inspection
│       ├── output/            # Output channels (file, MQTT, Kafka, etc.)
│       ├── security/          # Security rule engine
│       ├── packet_capture/    # PCAP/DPDK integration
│       └── dynamic_conf/      # Runtime reconfiguration
├── docs/                      # Documentation
├── test/                      # Test cases and sample data
├── mk/                        # Makefile build rules
├── script/                    # Installation scripts
├── mmt-probe.conf             # Default configuration file
├── Dockerfile                 # Container image definition
└── Makefile                   # Build system
```

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Language | C (with C++11 support) |
| Build System | GNU Make |
| Packet Capture | libpcap / DPDK |
| Configuration | libconfuse |
| DPI Engine | [MMT-DPI](https://github.com/montimage/mmt-dpi) |
| Security Engine | [MMT-Security](https://github.com/montimage/mmt-security) |
| Containerization | Docker (Ubuntu 22.04) |

## Documentation

- [Installation Guide](./docs/installation.md) -- Compilation, build options, and execution
- [Configuration Guide](./docs/configuration.md) -- Configuration file parameters
- [Architecture Overview](./docs/architecture.md) -- System design and process model
- [Data Format](./docs/data-format.md) -- Output report format specification
- [DPDK Capture](./docs/dpdk-capture.md) -- DPDK packet capture setup
- [Dynamic Configuration](./docs/dynamic_conf.md) -- Runtime reconfiguration
- [Development Guide](./docs/DEVELOPMENT.md) -- Development setup and debugging
- [Deployment Guide](./docs/DEPLOYMENT.md) -- Production deployment
- [Changelog](./CHANGELOG.md) -- Version history

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) before submitting a pull request.

## License

This project is licensed under the Apache License 2.0 -- see the [LICENSE](LICENSE) file for details.

## About

MMT-Probe is developed and maintained by [Montimage](https://montimage.com).
