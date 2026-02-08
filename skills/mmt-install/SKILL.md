---
name: mmt-install
version: 1.0.0
description: Install MMT-Probe and its dependencies from source, packages, or Docker
---

# MMT-Probe Installation

Guide the user through installing MMT-Probe and all its dependencies.

## Triggers

Use this skill when the user asks to:
- Install MMT-Probe or MMT-DPI
- Set up the build environment
- Compile MMT-Probe from source
- Install dependencies (hiredis, librdkafka, mongo-c-driver, etc.)
- Create .deb or .rpm packages
- Run MMT-Probe via Docker

## Important: Docker / Non-root Environments

Inside Docker containers you typically run as root, so `sudo` is neither available nor needed. All commands below use `sudo` for host installations. **In Docker containers, omit `sudo`** from every command (or define an alias: `alias sudo=''`).

To detect if you are in a Docker container:

```bash
if [ -f /.dockerenv ] || grep -q docker /proc/1/cgroup 2>/dev/null; then
    SUDO=""
    echo "Docker detected: running without sudo"
else
    SUDO="sudo"
    echo "Host detected: using sudo"
fi
```

Then use `$SUDO` in place of `sudo` throughout (e.g., `$SUDO apt-get update`).

## Prerequisites Check

### Detect the OS

```bash
OS_ID=$(grep -oP '(?<=^ID=).+' /etc/os-release | tr -d '"')
OS_VERSION=$(grep -oP '(?<=^VERSION_ID=).+' /etc/os-release | tr -d '"')
echo "Detected OS: $OS_ID $OS_VERSION"
```

### Required Software

| Software    | Min Version | Purpose                      |
|-------------|-------------|------------------------------|
| GCC         | 4.9+        | C compiler                   |
| G++         | 4.9+        | C++ compiler (static link)   |
| GNU Make    | 3.81+       | Build system                 |
| Git         | 2.0+        | Source code management       |
| libconfuse  | any         | Configuration file parsing   |
| libpcap     | any         | Packet capture               |
| MMT-DPI     | 1.7.1+      | Deep Packet Inspection lib   |

## Step 1: System Package Installation

### Debian/Ubuntu

```bash
$SUDO apt-get update
$SUDO apt-get install -y build-essential gcc g++ cpp cmake git curl
$SUDO apt-get install -y libconfuse-dev libpcap-dev
```

### RHEL/CentOS/Fedora

```bash
$SUDO yum groupinstall -y "Development Tools"
$SUDO yum install -y cmake git curl
$SUDO yum install -y libconfuse-devel libpcap-devel
```

### Verify

```bash
gcc --version    # >= 4.9
g++ --version    # >= 4.9
make --version   # >= 3.81
```

## Step 2: Install MMT-DPI (Mandatory)

MMT-DPI is the core deep packet inspection library. It **must** be installed before MMT-Probe.

```bash
TMP_DIR=$(mktemp -d -t mmt-setup-XXXXXXXXXX)
cd "$TMP_DIR"
git clone https://github.com/montimage/mmt-dpi.git mmt-dpi
cd mmt-dpi/sdk
make -j$(nproc)
$SUDO make install
$SUDO ldconfig
```

Verify: `ls /opt/mmt/dpi/lib/libmmt_core.so` and `ls /opt/mmt/dpi/include/`

## Step 3: Optional Module Dependencies

Only install libraries for the modules you need. Skip any you do not need.

| Module             | Library           | Version | Install Command |
|--------------------|-------------------|---------|-----------------|
| `REDIS_MODULE`     | hiredis           | v1.0.2  | See 3a below    |
| `KAFKA_MODULE`     | librdkafka        | v1.8.2  | See 3b below    |
| `MONGODB_MODULE`   | mongo-c-driver    | 1.9.5   | See 3c below    |
| `MQTT_MODULE`      | libpaho-mqtt      | any     | See 3d below    |
| `SECURITY_MODULE`  | MMT-Security      | any     | See 3e below    |

### 3a. Redis (hiredis v1.0.2)

```bash
cd "$TMP_DIR"
git clone https://github.com/redis/hiredis.git hiredis
cd hiredis && git checkout v1.0.2
make -j$(nproc) && $SUDO make install && $SUDO ldconfig
```

### 3b. Kafka (librdkafka v1.8.2)

```bash
$SUDO apt-get install -y libsasl2-dev libssl-dev  # Debian/Ubuntu
cd "$TMP_DIR"
git clone https://github.com/edenhill/librdkafka.git librdkafka
cd librdkafka && git checkout v1.8.2
./configure && make -j$(nproc) && $SUDO make install && $SUDO ldconfig
```

### 3c. MongoDB (mongo-c-driver 1.9.5)

```bash
$SUDO apt-get install -y pkg-config libssl-dev libsasl2-dev  # Debian/Ubuntu
cd "$TMP_DIR"
curl -Lk --output mongo-c.tar.gz https://github.com/mongodb/mongo-c-driver/releases/download/1.9.5/mongo-c-driver-1.9.5.tar.gz
tar xzf mongo-c.tar.gz && cd mongo-c-driver-1.9.5
./configure --disable-automatic-init-and-cleanup
make -j$(nproc) && $SUDO make install && $SUDO ldconfig
```

### 3d. MQTT (libpaho-mqtt)

```bash
$SUDO apt-get install -y libpaho-mqtt-dev  # Debian/Ubuntu
```

### 3e. MMT-Security

```bash
$SUDO apt-get install -y libxml2-dev libpcap-dev libconfuse-dev
cd "$TMP_DIR"
git clone https://github.com/Montimage/mmt-security.git mmt-security
cd mmt-security
make clean-all
make -j1  # Must use single thread for header generation ordering
$SUDO make install && $SUDO ldconfig
```

Verify: `ls /opt/mmt/security/lib/libmmt_security2.*`

## Step 4: Compile MMT-Probe

Navigate to the MMT-Probe source directory.

### Minimal build (file output + PCAP only)

```bash
make clean
make -j$(nproc) compile
```

### Build with selected modules

Combine any module targets before `compile`:

```bash
make -j$(nproc) KAFKA_MODULE REDIS_MODULE SECURITY_MODULE PCAP_DUMP_MODULE QOS_MODULE SOCKET_MODULE compile
```

### Available module targets

| Module Target             | Requires            |
|---------------------------|----------------------|
| `REDIS_MODULE`            | hiredis              |
| `KAFKA_MODULE`            | librdkafka           |
| `MONGODB_MODULE`          | mongo-c-driver       |
| `MQTT_MODULE`             | libpaho-mqtt         |
| `SECURITY_MODULE`         | MMT-Security + libxml2 |
| `PCAP_DUMP_MODULE`        | (none)               |
| `QOS_MODULE`              | (none)               |
| `SOCKET_MODULE`           | (none)               |
| `LTE_MODULE`              | (none)               |
| `DYNAMIC_CONFIG_MODULE`   | (none)               |
| `TCP_REASSEMBLY_MODULE`   | (none)               |
| `HTTP_RECONSTRUCT_MODULE` | (none, implies TCP)  |
| `FTP_RECONSTRUCT_MODULE`  | (none, implies TCP)  |

### Build ALL modules

```bash
make -j$(nproc) ALL_MODULES compile
```

> Requires all optional libraries from Step 3 to be installed.

### Build options

| Option           | Effect                                       |
|------------------|----------------------------------------------|
| `DEBUG`          | Enable debug symbols (`-g -O0`)              |
| `VERBOSE`        | Print detailed compilation commands          |
| `STATIC_LINK`    | Embed MMT-DPI and MMT-Security into binary   |
| `DISABLE_REPORT` | Skip DPI statistics                          |
| `SIMPLE_REPORT`  | Minimal session reports (for MMT-Box)        |
| `MMT_BASE=/path` | Custom install prefix (default: `/opt/mmt`)  |

### DPDK capture (instead of PCAP)

```bash
export RTE_SDK=/path/to/dpdk
export RTE_TARGET=build
make -j$(nproc) DPDK_CAPTURE compile
```

## Step 5: Install

```bash
$SUDO make install
# Or with modules:
$SUDO make KAFKA_MODULE REDIS_MODULE SECURITY_MODULE install
```

Installs to `/opt/mmt/probe/` (or `$MMT_BASE/probe/`):
- `bin/probe` — executable
- `mmt-probe.conf` — configuration file
- `result/report/online/` — default report output

### Create packages (optional)

```bash
make deb                          # Debian .deb
make KAFKA_MODULE REDIS_MODULE deb  # .deb with modules
make rpm                          # RHEL .rpm
```

## Docker Alternative

```bash
# Pull pre-built image
docker pull ghcr.io/montimage/mmt-probe:latest

# Or build from source
cd /path/to/mmt-probe
docker build -t mmt-probe:local .
```

## Automated Script

For a fully automated installation with all modules on Debian/Ubuntu:

```bash
$SUDO ./script/install-from-source.sh
```

This installs all dependencies, compiles with all modules, and creates a `.deb` package.

## Verification

```bash
./probe -v                  # Print version (e.g., mmt-probe 1.6.0)
./probe -h                  # Print usage help
$SUDO ./probe -t test/UA-Exp01.pcap -Xfile-output.output-dir=/tmp/mmt-test/
ls -la /tmp/mmt-test/       # Should contain report files
ldd /opt/mmt/probe/bin/probe  # All libraries resolved (no "not found")
```

## Troubleshooting

| Error | Cause | Solution |
|-------|-------|----------|
| `ERROR: Not found MMT-DPI at folder /opt/mmt/dpi` | MMT-DPI not installed | Install MMT-DPI (Step 2) |
| `Not found MMT-Security at /opt/mmt/security` | MMT-Security missing | Install it (Step 3e) or remove `SECURITY_MODULE` |
| `-lhiredis` not found | hiredis missing | Install (Step 3a) or remove `REDIS_MODULE` |
| `-lrdkafka` not found | librdkafka missing | Install (Step 3b) or remove `KAFKA_MODULE` |
| `-lmongoc-1.0` not found | mongo-c-driver missing | Install (Step 3c) or remove `MONGODB_MODULE` |
| `-lpaho-mqtt3c` not found | libpaho-mqtt missing | Install (Step 3d) or remove `MQTT_MODULE` |
| `error while loading shared libraries` | Library not in LD path | Run `ldconfig` (or `sudo ldconfig` on host) |
| Library path issues | `/usr/local/lib` not in linker path | `ldconfig -p \| grep <lib>` to check |
| `sudo: command not found` | Running inside Docker | Omit `sudo` — you are already root in Docker |

## Important Notes

- Always run `make clean` before recompiling with different modules.
- Run `ldconfig` (or `sudo ldconfig` on host) after installing any shared library.
- DPDK mode requires hugepage allocation: `echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages`

## Cross-references

- After installation, use `/mmt-configure` to set up configuration.
- To run the probe, use `/mmt-operate`.
- For general help, use `/mmt-help`.
