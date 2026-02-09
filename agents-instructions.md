# AI Agent Setup Instructions for MMT-Probe

## Overview

MMT-Probe is a C-based network traffic analysis probe developed by [Montimage](https://www.montimage.com). It performs deep packet inspection (DPI), security analysis, and protocol reconstruction on live or offline network traffic. This document provides step-by-step instructions for an AI agent to perform a complete from-scratch installation and setup.

**Repository**: <https://github.com/montimage/mmt-probe>
**Version**: 1.6.0
**License**: Apache License 2.0

---

## Prerequisites

### Required Software

| Software         | Minimum Version | Purpose                           |
|------------------|-----------------|-----------------------------------|
| GCC              | 4.9+            | C compiler                        |
| G++              | 4.9+            | C++ compiler (static linking)     |
| GNU Make         | 3.81+           | Build system                      |
| Git              | 2.0+            | Source code management             |
| libconfuse       | any             | Configuration file parsing         |
| libpcap          | any             | Packet capture (default backend)   |
| MMT-DPI          | 1.7.1+          | Deep Packet Inspection library     |

### Optional Software (per module)

| Software         | Required By           | Purpose                     |
|------------------|-----------------------|-----------------------------|
| hiredis v1.0.2   | `REDIS_MODULE`        | Redis client library        |
| librdkafka v1.8.2| `KAFKA_MODULE`        | Kafka client library        |
| mongo-c-driver 1.9.5 | `MONGODB_MODULE` | MongoDB client library      |
| libpaho-mqtt     | `MQTT_MODULE`         | MQTT client library         |
| MMT-Security     | `SECURITY_MODULE`     | Security rule verification  |
| libxml2          | `SECURITY_MODULE`     | XML parsing                 |
| DPDK             | `DPDK_CAPTURE`        | High-performance packet I/O |
| sysrepo/netopeer2| `NETCONF_MODULE`      | NETCONF protocol support    |
| gperf            | `gperf` target        | Perfect hash generation     |

### System Requirements

- **OS**: Linux (Ubuntu 22.04 recommended; Debian, CentOS, Fedora supported)
- **Architecture**: x86_64
- **Privileges**: Root or `CAP_NET_RAW` for packet capture
- **RAM**: Minimum 100 MB; 2 GB+ for DPDK mode (hugepages)
- **Disk**: ~50 MB for installation + space for reports

---

## Setup Sequence

### 1. System Package Installation

#### Auto-detect OS

```bash
# Detect distribution
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
OS_VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"')
echo "Detected OS: $OS_ID $OS_VERSION"
```

#### Install base packages

**Debian/Ubuntu:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential gcc g++ cpp cmake git curl
sudo apt-get install -y libconfuse-dev libpcap-dev
```

**RHEL/CentOS/Fedora:**

```bash
sudo yum groupinstall -y "Development Tools"
sudo yum install -y cmake git curl
sudo yum install -y libconfuse-devel libpcap-devel
```

#### Verification

```bash
gcc --version   # Must be >= 4.9
g++ --version   # Must be >= 4.9
make --version  # Must be >= 3.81
git --version
pkg-config --modversion libconfuse 2>/dev/null || dpkg -s libconfuse-dev 2>/dev/null | grep Version
```

---

### 2. Install MMT-DPI (Required Dependency)

MMT-DPI is the core deep packet inspection library. It **must** be installed before MMT-Probe.

```bash
# Create a temporary build directory
TMP_DIR=$(mktemp -d -t mmt-setup-XXXXXXXXXX)
cd "$TMP_DIR"

# Clone and build MMT-DPI
git clone https://github.com/montimage/mmt-dpi.git mmt-dpi
cd mmt-dpi/sdk
make -j$(nproc)
sudo make install
sudo ldconfig
```

#### Verification

```bash
ls /opt/mmt/dpi/lib/libmmt_core.so   # Should exist
ls /opt/mmt/dpi/include/              # Should contain header files
```

---

### 3. Install Optional Output Module Dependencies

Install only the libraries needed for desired output modules. Skip any module you do not need.

#### 3a. Redis Output (`REDIS_MODULE`)

```bash
cd "$TMP_DIR"
git clone https://github.com/redis/hiredis.git hiredis
cd hiredis
git checkout v1.0.2
make -j$(nproc)
sudo make install
sudo ldconfig
```

**Verification**: `ls /usr/local/lib/libhiredis.*`

#### 3b. Kafka Output (`KAFKA_MODULE`)

```bash
sudo apt-get install -y libsasl2-dev libssl-dev   # Debian/Ubuntu
# sudo yum install -y cyrus-sasl-devel openssl-devel  # RHEL/CentOS

cd "$TMP_DIR"
git clone https://github.com/edenhill/librdkafka.git librdkafka
cd librdkafka
git checkout v1.8.2
./configure
make -j$(nproc)
sudo make install
sudo ldconfig
```

**Verification**: `ls /usr/local/lib/librdkafka.*`

#### 3c. MongoDB Output (`MONGODB_MODULE`)

```bash
sudo apt-get install -y pkg-config libssl-dev libsasl2-dev   # Debian/Ubuntu

cd "$TMP_DIR"
curl -Lk --output mongo-c.tar.gz https://github.com/mongodb/mongo-c-driver/releases/download/1.9.5/mongo-c-driver-1.9.5.tar.gz
tar xzf mongo-c.tar.gz
cd mongo-c-driver-1.9.5
./configure --disable-automatic-init-and-cleanup
make -j$(nproc)
sudo make install
sudo ldconfig
```

**Verification**: `pkg-config --modversion libmongoc-1.0`

#### 3d. MQTT Output (`MQTT_MODULE`)

```bash
sudo apt-get install -y libpaho-mqtt-dev   # Debian/Ubuntu
```

**Verification**: `dpkg -s libpaho-mqtt-dev 2>/dev/null | grep Status`

#### 3e. MMT-Security (`SECURITY_MODULE`)

```bash
sudo apt-get install -y libxml2-dev libpcap-dev libconfuse-dev

cd "$TMP_DIR"
git clone https://github.com/Montimage/mmt-security.git mmt-security
cd mmt-security
make clean-all
make -j1   # Must use single thread to handle header generation ordering
sudo make install
sudo ldconfig
```

**Verification**: `ls /opt/mmt/security/lib/libmmt_security2.*`

---

### 4. Compile MMT-Probe

Navigate to the MMT-Probe source directory.

```bash
cd /path/to/mmt-probe   # Replace with actual path
```

#### 4a. Minimal Build (file output + PCAP capture only)

```bash
make clean
make -j$(nproc) compile
```

#### 4b. Build with Selected Modules

Specify modules as make targets. Combine any of:

| Module Target            | Requires Library     |
|--------------------------|----------------------|
| `REDIS_MODULE`           | hiredis              |
| `KAFKA_MODULE`           | librdkafka           |
| `MONGODB_MODULE`         | mongo-c-driver       |
| `MQTT_MODULE`            | libpaho-mqtt         |
| `SECURITY_MODULE`        | MMT-Security         |
| `PCAP_DUMP_MODULE`       | (none)               |
| `QOS_MODULE`             | (none)               |
| `SOCKET_MODULE`          | (none)               |
| `LTE_MODULE`             | (none)               |
| `DYNAMIC_CONFIG_MODULE`  | (none)               |
| `TCP_REASSEMBLY_MODULE`  | (none)               |
| `HTTP_RECONSTRUCT_MODULE`| (none, implies TCP)  |
| `FTP_RECONSTRUCT_MODULE` | (none, implies TCP)  |

Example with multiple modules:

```bash
make -j$(nproc) KAFKA_MODULE REDIS_MODULE SECURITY_MODULE PCAP_DUMP_MODULE QOS_MODULE SOCKET_MODULE compile
```

#### 4c. Build with ALL Modules

```bash
make -j$(nproc) ALL_MODULES compile
```

> **Note**: `ALL_MODULES` requires all optional libraries from Step 3 to be installed.

#### 4d. Build with DPDK Capture (instead of PCAP)

```bash
export RTE_SDK=/path/to/dpdk
export RTE_TARGET=build
make -j$(nproc) DPDK_CAPTURE compile
```

#### Build Options

| Option         | Effect                                         |
|----------------|-------------------------------------------------|
| `DEBUG`        | Enable debug symbols (`-g -O0`) for gdb         |
| `VERBOSE`      | Print detailed compilation commands              |
| `STATIC_LINK`  | Embed MMT-DPI and MMT-Security into the binary   |
| `DISABLE_REPORT`| Skip DPI statistics (for security/dump only)   |
| `SIMPLE_REPORT`| Minimal session reports (for MMT-Box)           |
| `MMT_BASE=/path`| Custom installation prefix (default: /opt/mmt) |

#### Verification

```bash
./probe -v   # Should print version: 1.6.0 and git hash
./probe -h   # Should print usage help
```

---

### 5. Install MMT-Probe

```bash
sudo make install
# Or with modules:
sudo make KAFKA_MODULE REDIS_MODULE SECURITY_MODULE install
```

This installs to `/opt/mmt/probe/` (or `$MMT_BASE/probe/` if `MMT_BASE` is set):

```
/opt/mmt/probe/
├── bin/probe              # Executable
├── mmt-probe.conf         # Configuration file
└── result/report/online/  # Default report output directory
```

#### Create Packages (optional)

```bash
# Debian/Ubuntu .deb package
make deb
# or with modules:
make KAFKA_MODULE REDIS_MODULE deb

# RHEL/CentOS .rpm package
make rpm
```

#### Verification

```bash
ls -la /opt/mmt/probe/bin/probe
/opt/mmt/probe/bin/probe -v
```

---

### 6. Configuration

The default configuration file is `mmt-probe.conf`. After installation it is located at `/opt/mmt/probe/mmt-probe.conf`.

#### Key Configuration Sections

| Section            | Purpose                                 | Default State |
|--------------------|-----------------------------------------|---------------|
| `input`            | Capture source (interface or PCAP file) | `enp0s3`      |
| `file-output`      | Write reports to files                  | **enabled**   |
| `redis-output`     | Publish reports to Redis                | disabled      |
| `kafka-output`     | Publish reports to Kafka                | disabled      |
| `mongodb-output`   | Store reports in MongoDB                | disabled      |
| `mqtt-output`      | Publish reports via MQTT                | disabled      |
| `socket-output`    | Send reports via Unix/TCP/UDP socket    | disabled      |
| `security`         | MMT-Security rule verification          | disabled      |
| `session-report`   | Per-session DPI statistics              | **enabled**   |
| `dump-pcap`        | Dump packets to PCAP files              | disabled      |
| `thread-nb`        | Number of processing threads            | `0` (single)  |

#### Minimal Configuration Adjustments

At minimum, update the capture interface:

```
input {
    mode = ONLINE
    source = "<YOUR_INTERFACE>"   # e.g., "eth0", "ens33"
}
```

Configuration can also be overridden at runtime via `-X` flags:

```bash
sudo ./probe -i eth0 -Xfile-output.enable=true -Xfile-output.output-dir=/tmp/
```

#### List All Overridable Parameters

```bash
./probe -x
```

---

### 7. Execution

#### 7a. Run Locally (foreground)

```bash
# Live capture on an interface
sudo ./probe -i eth0

# Offline analysis of a PCAP file
sudo ./probe -t /path/to/capture.pcap

# With a specific configuration file
sudo ./probe -c mmt-probe.conf

# Override config parameters at runtime
sudo ./probe -i eth0 -Xfile-output.enable=true -Xsecurity.enable=true
```

#### 7b. Run as a Systemd Service

Available only when installed to the default path `/opt/mmt/probe/`.

```bash
sudo systemctl start mmt-probe
sudo systemctl status mmt-probe
sudo systemctl stop mmt-probe

# View logs
journalctl -t mmt-probe
```

#### 7c. Run with Docker

```bash
# Pull the image
docker pull ghcr.io/montimage/mmt-probe:latest

# Run with live capture
docker run --network=host ghcr.io/montimage/mmt-probe:latest \
    mmt-probe -i eth0 -Xfile-output.enable=true

# Run with a PCAP file
docker run -v /path/to/pcaps:/data ghcr.io/montimage/mmt-probe:latest \
    mmt-probe -t /data/capture.pcap
```

#### 7d. Build Docker Image from Source

```bash
cd /path/to/mmt-probe
docker build -t mmt-probe:local .
```

---

### 8. Verification Steps

Run these after installation to confirm everything is working:

```bash
# 1. Check the binary exists and runs
/opt/mmt/probe/bin/probe -v
# Expected: prints version info (e.g., "mmt-probe 1.6.0 ...")

# 2. Check help output
/opt/mmt/probe/bin/probe -h
# Expected: prints usage with -v, -c, -t, -i, -X, -x, -h options

# 3. Test offline analysis with sample PCAP
sudo /opt/mmt/probe/bin/probe -t test/UA-Exp01.pcap -Xfile-output.output-dir=/tmp/mmt-test/
# Expected: processes packets and generates report files in /tmp/mmt-test/

# 4. Verify report output was created
ls -la /tmp/mmt-test/
# Expected: CSV or JSON report files

# 5. Check linked libraries (runtime dependencies)
ldd /opt/mmt/probe/bin/probe
# Expected: all shared libraries resolved (no "not found")

# 6. Check systemd service (if installed to /opt/mmt/probe/)
sudo systemctl status mmt-probe
# Expected: loaded (may be inactive if not started)
```

---

## Manual Input Summary

| Input               | Description                                       | Required | Default             |
|---------------------|---------------------------------------------------|----------|---------------------|
| Network interface   | Interface name for live capture                   | Yes*     | `enp0s3`            |
| PCAP file path      | Path to PCAP file for offline analysis            | Yes*     | -                   |
| `MMT_BASE`          | Custom installation prefix                        | No       | `/opt/mmt`          |
| Module selection    | Which optional modules to enable                  | No       | File output + PCAP  |
| Output endpoints    | Redis/Kafka/MongoDB/MQTT server addresses         | No       | `localhost`         |
| Thread count        | Number of processing threads                      | No       | `0` (single thread) |

\* Either a network interface or PCAP file path is required for execution.

---

## Permission Gates

The following operations require explicit user permission:

- [ ] **Install system packages** (`apt-get install`, `yum install`)
- [ ] **Clone external repositories** (MMT-DPI, MMT-Security, hiredis, librdkafka, mongo-c-driver)
- [ ] **Run `make install` with sudo** (writes to `/opt/mmt/` and `/usr/local/`)
- [ ] **Run `ldconfig` with sudo** (updates shared library cache)
- [ ] **Modify system configuration** (systemd service file)
- [ ] **Set network interface to promiscuous mode** (via `probe -i`)
- [ ] **Create/modify `/opt/mmt/probe/mmt-probe.conf`** (runtime configuration)

---

## Environment Variables Reference

### Build-Time

| Variable           | Description                                  | Default       |
|--------------------|----------------------------------------------|---------------|
| `MMT_BASE`         | Base installation directory for MMT tools    | `/opt/mmt`    |
| `MMT_DPI_DIR`      | Path to MMT-DPI installation                 | `$MMT_BASE/dpi` |
| `MMT_SECURITY_DIR` | Path to MMT-Security installation            | `$MMT_BASE/security` |
| `RTE_SDK`          | DPDK SDK path (DPDK mode only)               | _(unset)_     |
| `RTE_TARGET`       | DPDK build target (DPDK mode only)           | `build`       |
| `DEBIAN_FRONTEND`  | Suppress apt interactive prompts             | _(unset)_     |

### Runtime (Docker/Environment)

| Variable                                          | Description                          |
|---------------------------------------------------|--------------------------------------|
| `MMT_SEC_5G_DOS_NGAP_INITIALUEMESSAGE_MS_LIMIT`  | 5G DoS detection threshold (ms)      |
| `MMT_SEC_5G_DOS_HTTP2_MS_LIMIT`                   | 5G HTTP/2 DoS detection threshold    |

---

## Automated Installation (One-Command)

For a fully automated installation with all modules on Debian/Ubuntu:

```bash
sudo ./script/install-from-source.sh
```

This script:
1. Installs all system dependencies
2. Clones and installs hiredis v1.0.2
3. Clones and installs librdkafka v1.8.2
4. Downloads and installs mongo-c-driver 1.9.5
5. Installs libpaho-mqtt
6. Clones and installs MMT-DPI
7. Clones and installs MMT-Security
8. Compiles MMT-Probe with all modules (`KAFKA_MODULE MONGODB_MODULE PCAP_DUMP_MODULE QOS_MODULE REDIS_MODULE MQTT_MODULE SECURITY_MODULE SOCKET_MODULE LTE_MODULE`)
9. Creates a `.deb` package

> **Requires**: Root privileges, Ubuntu/Debian, and internet access.

---

## Troubleshooting

### Compilation Errors

| Error                                          | Cause                              | Solution                                       |
|------------------------------------------------|------------------------------------|-------------------------------------------------|
| `ERROR: Not found MMT-DPI at folder /opt/mmt/dpi` | MMT-DPI not installed           | Install MMT-DPI first (Step 2)                  |
| `Not found MMT-Security at /opt/mmt/security`  | MMT-Security not installed        | Install MMT-Security (Step 3e) or remove `SECURITY_MODULE` |
| `-lhiredis` not found                          | hiredis not installed              | Install hiredis (Step 3a) or remove `REDIS_MODULE` |
| `-lrdkafka` not found                          | librdkafka not installed           | Install librdkafka (Step 3b) or remove `KAFKA_MODULE` |
| `-lmongoc-1.0` not found                       | mongo-c-driver not installed       | Install mongo-c-driver (Step 3c) or remove `MONGODB_MODULE` |
| `-lpaho-mqtt3c` not found                       | libpaho-mqtt not installed        | Install libpaho-mqtt (Step 3d) or remove `MQTT_MODULE` |

### Runtime Errors

| Error                                          | Cause                              | Solution                                       |
|------------------------------------------------|------------------------------------|-------------------------------------------------|
| `error while loading shared libraries`         | Library not in LD path             | Run `sudo ldconfig`                             |
| `Permission denied` on interface               | Missing root/CAP_NET_RAW           | Run with `sudo` or set capabilities             |
| No output files generated                      | `file-output.enable` is false      | Set `-Xfile-output.enable=true`                 |
| Probe exits immediately                        | License check enabled but no key   | Remove `LICENSE_MODULE` or provide `license.key` |

### Common Issues

- **Clean build after module changes**: Run `make clean` before recompiling with different modules.
- **Library path issues**: Ensure `/usr/local/lib` is in the linker path. Check with `ldconfig -p | grep <lib>`.
- **DPDK hugepages**: Allocate hugepages before running DPDK mode: `echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`.

---

## Next Steps

After successful setup:

1. **Configure for your network**: Edit `mmt-probe.conf` to set your capture interface and enable desired reports/outputs.
2. **Integrate with MMT-Operator**: Connect to the [MMT-Operator](https://github.com/montimage/mmt-operator) web interface for visualization.
3. **Add security rules**: Enable `SECURITY_MODULE` and configure custom rules for intrusion detection.
4. **Deploy at scale**: Use Docker Compose or Kubernetes manifests in `docs/guide/k8s/` for production deployments.
5. **Monitor performance**: Use `system-report` in the config to track CPU/memory usage of the probe itself.

---

## Quick Reference: Common Commands

```bash
# Compile (minimal)
make compile

# Compile (all modules)
make ALL_MODULES compile

# Install
sudo make install

# Run on interface
sudo ./probe -i eth0

# Run on PCAP file
sudo ./probe -t file.pcap

# Run with config
sudo ./probe -c mmt-probe.conf

# Override config at runtime
sudo ./probe -i eth0 -Xsecurity.enable=true -Xfile-output.output-dir=/tmp/

# Create .deb package
make deb

# Clean build
make clean

# View service logs
journalctl -t mmt-probe
```
