# MMT-Probe AI Agent Installation Instructions

This document provides comprehensive instructions for an AI agent to perform a complete, from-scratch installation and setup of MMT-Probe. The process is divided into three distinct phases, each requiring explicit user approval before proceeding.

## Table of Contents
- [Project Overview](#project-overview)
- [Supported Platforms](#supported-platforms)
- [Prerequisites](#prerequisites)
- [Three-Phase Execution Model](#three-phase-execution-model)
  - [Phase 1: Research](#phase-1-research)
  - [Phase 2: Plan](#phase-2-plan)
  - [Phase 3: Execute](#phase-3-execute)
- [Appendix A: Platform-Specific Commands](#appendix-a-platform-specific-commands)
- [Appendix B: Configuration Reference](#appendix-b-configuration-reference)
- [Appendix C: Troubleshooting](#appendix-c-troubleshooting)

---

## Project Overview

**MMT-Probe** (Montimage Monitoring Tool Probe) is a high-performance network traffic analysis tool that performs online and offline Deep Packet Inspection (DPI) on network traffic.

| Property | Value |
|----------|-------|
| Repository | https://github.com/montimage/mmt-probe |
| Language | C with some C++ |
| Build System | GNU Make |
| Default Install Path | `/opt/mmt/probe` |
| Configuration Format | libconfuse (structured text) |

### Key Features
- Real-time and offline packet analysis
- Deep Packet Inspection via MMT-DPI library
- Multiple output channels: File, Redis, Kafka, MongoDB, MQTT, Socket
- Security analysis via MMT-Security integration
- Multi-threaded processing with DPDK support (optional)

---

## Supported Platforms

| Platform | Package Manager | Tested Versions |
|----------|-----------------|-----------------|
| Ubuntu | apt | 20.04, 22.04, 24.04 |
| Debian | apt | 10, 11, 12 |
| RHEL | dnf/yum | 8, 9 |
| CentOS | dnf/yum | 8 Stream, 9 Stream |
| Rocky Linux | dnf | 8, 9 |
| AlmaLinux | dnf | 8, 9 |

---

## Prerequisites

Before starting, ensure:
1. Root or sudo access on the target system
2. Internet connectivity for downloading packages and repositories
3. At least 2GB free disk space
4. At least 1GB RAM available

---

## Three-Phase Execution Model

**CRITICAL**: Do not proceed to the next phase until the user explicitly approves.

---

## Phase 1: Research

**Objective**: Collect all necessary information about the installation environment and requirements.

### Task 1.1: Detect Operating System

Execute the following commands and record the results:

```bash
# Detect OS family and version
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS_NAME="$NAME"
    OS_VERSION="$VERSION_ID"
    OS_ID="$ID"
    OS_ID_LIKE="$ID_LIKE"
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_MANAGER="apt"
elif command -v dnf &> /dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &> /dev/null; then
    PKG_MANAGER="yum"
else
    PKG_MANAGER="unknown"
fi

# Output detection results
echo "OS_NAME: $OS_NAME"
echo "OS_VERSION: $OS_VERSION"
echo "OS_ID: $OS_ID"
echo "OS_ID_LIKE: $OS_ID_LIKE"
echo "PKG_MANAGER: $PKG_MANAGER"
```

**Success Criterion**: OS family and package manager identified
**Verification**: `$PKG_MANAGER` is one of: `apt`, `dnf`, `yum`

### Task 1.2: Check System Resources

```bash
# Check available disk space
df -h / | awk 'NR==2 {print "Disk Available: " $4}'

# Check available memory
free -h | awk '/^Mem:/ {print "Memory Available: " $7}'

# Check CPU cores (for parallel compilation)
nproc
```

**Success Criterion**: At least 2GB disk space, 1GB RAM available
**Verification**: Numeric comparison of values

### Task 1.3: Check Existing Installations

```bash
# Check if MMT-DPI is installed
if [ -d "/opt/mmt/dpi" ]; then
    echo "MMT-DPI: INSTALLED at /opt/mmt/dpi"
    ls -la /opt/mmt/dpi/lib/ 2>/dev/null
else
    echo "MMT-DPI: NOT INSTALLED"
fi

# Check if MMT-Security is installed
if [ -d "/opt/mmt/security" ]; then
    echo "MMT-Security: INSTALLED at /opt/mmt/security"
else
    echo "MMT-Security: NOT INSTALLED"
fi

# Check if MMT-Probe is installed
if [ -d "/opt/mmt/probe" ]; then
    echo "MMT-Probe: INSTALLED at /opt/mmt/probe"
    /opt/mmt/probe/probe -v 2>/dev/null || echo "Binary not executable"
else
    echo "MMT-Probe: NOT INSTALLED"
fi

# Check for existing configuration
if [ -f "/opt/mmt/probe/mmt-probe.conf" ]; then
    echo "Config: EXISTS at /opt/mmt/probe/mmt-probe.conf"
fi
```

**Success Criterion**: Existing installation status documented
**Verification**: Each component status recorded

### Task 1.4: Check Build Tools

```bash
# Check GCC version
gcc --version 2>/dev/null | head -n1 || echo "GCC: NOT INSTALLED"

# Check G++ version
g++ --version 2>/dev/null | head -n1 || echo "G++: NOT INSTALLED"

# Check CMake version
cmake --version 2>/dev/null | head -n1 || echo "CMake: NOT INSTALLED"

# Check Make version
make --version 2>/dev/null | head -n1 || echo "Make: NOT INSTALLED"

# Check Git version
git --version 2>/dev/null || echo "Git: NOT INSTALLED"
```

**Success Criterion**: Build tools availability documented
**Verification**: GCC version >= 4.9 (if installed)

### Task 1.5: Identify Network Interfaces

```bash
# List all network interfaces
ip link show | grep -E '^[0-9]+:' | awk -F': ' '{print $2}'

# Alternative for older systems
ifconfig -a 2>/dev/null | grep -E '^[a-z]' | awk '{print $1}' | tr -d ':'
```

**Success Criterion**: Available network interfaces listed
**Verification**: At least one interface found (excluding `lo`)

### Task 1.6: Check Required Libraries

```bash
# Check libpcap
ldconfig -p | grep libpcap || echo "libpcap: NOT FOUND"

# Check libconfuse
ldconfig -p | grep libconfuse || echo "libconfuse: NOT FOUND"

# Check libxml2
ldconfig -p | grep libxml2 || echo "libxml2: NOT FOUND"

# Check libssl
ldconfig -p | grep libssl || echo "libssl: NOT FOUND"

# Check libsasl2
ldconfig -p | grep libsasl2 || echo "libsasl2: NOT FOUND"

# Check hiredis
ldconfig -p | grep hiredis || echo "hiredis: NOT FOUND"

# Check librdkafka
ldconfig -p | grep rdkafka || echo "librdkafka: NOT FOUND"

# Check libmongoc
ldconfig -p | grep mongoc || echo "libmongoc: NOT FOUND"

# Check paho-mqtt
ldconfig -p | grep paho-mqtt || echo "paho-mqtt: NOT FOUND"
```

**Success Criterion**: Library availability documented
**Verification**: Each library status recorded

### Task 1.7: Generate research.md

Create a `research.md` file in the current working directory with all findings:

```markdown
# MMT-Probe Installation Research Report

Generated: [TIMESTAMP]

## System Information

| Property | Value |
|----------|-------|
| OS Name | [OS_NAME] |
| OS Version | [OS_VERSION] |
| OS ID | [OS_ID] |
| Package Manager | [PKG_MANAGER] |
| CPU Cores | [NPROC] |
| Available Disk | [DISK_AVAIL] |
| Available Memory | [MEM_AVAIL] |

## Existing Installations

| Component | Status | Path |
|-----------|--------|------|
| MMT-DPI | [INSTALLED/NOT INSTALLED] | [PATH] |
| MMT-Security | [INSTALLED/NOT INSTALLED] | [PATH] |
| MMT-Probe | [INSTALLED/NOT INSTALLED] | [PATH] |

## Build Tools

| Tool | Status | Version |
|------|--------|---------|
| GCC | [INSTALLED/NOT INSTALLED] | [VERSION] |
| G++ | [INSTALLED/NOT INSTALLED] | [VERSION] |
| CMake | [INSTALLED/NOT INSTALLED] | [VERSION] |
| Make | [INSTALLED/NOT INSTALLED] | [VERSION] |
| Git | [INSTALLED/NOT INSTALLED] | [VERSION] |

## Network Interfaces

[LIST OF INTERFACES]

## Required Libraries

| Library | Status |
|---------|--------|
| libpcap | [FOUND/NOT FOUND] |
| libconfuse | [FOUND/NOT FOUND] |
| libxml2 | [FOUND/NOT FOUND] |
| libssl | [FOUND/NOT FOUND] |
| libsasl2 | [FOUND/NOT FOUND] |
| hiredis | [FOUND/NOT FOUND] |
| librdkafka | [FOUND/NOT FOUND] |
| libmongoc | [FOUND/NOT FOUND] |
| paho-mqtt | [FOUND/NOT FOUND] |

## Identified Ambiguities / Questions for User

1. [List any unclear requirements]
2. [List any decisions needed]

## Recommendations

- [Recommendation 1]
- [Recommendation 2]
```

### Task 1.8: User Verification

**STOP HERE AND WAIT FOR USER APPROVAL**

Present a summary to the user:
1. Show detected OS and package manager
2. List components that need to be installed
3. Show any questions or ambiguities identified
4. Ask user to review `research.md` for complete details
5. Request explicit approval to proceed to Phase 2

---

## Phase 2: Plan

**Objective**: Create a comprehensive, detailed plan for installation and setup.

### Task 2.1: Create Task Sequence

Based on the research findings, generate a numbered task sequence. The default installation includes ALL modules.

#### Default Task Sequence (All Modules)

```
TASK SEQUENCE FOR MMT-PROBE INSTALLATION
========================================

PRE-INSTALLATION
----------------
P1. [HIGH-RISK] Update system package cache
P2. [HIGH-RISK] Install base development tools

DEPENDENCY INSTALLATION
-----------------------
D1. [HIGH-RISK] Install system libraries (libconfuse, libpcap, libxml2, libssl, libsasl2)
D2. Build and install hiredis v1.0.2 (Redis client library)
D3. Build and install librdkafka v1.8.2 (Kafka client library)
D4. Build and install mongo-c-driver v1.9.5 (MongoDB client library)
D5. [HIGH-RISK] Install libpaho-mqtt-dev (MQTT client library)

CORE COMPONENTS
---------------
C1. Clone and build MMT-DPI from source
C2. [HIGH-RISK] Install MMT-DPI to /opt/mmt/dpi
C3. Clone and build MMT-Security from source
C4. [HIGH-RISK] Install MMT-Security to /opt/mmt/security

MMT-PROBE INSTALLATION
----------------------
M1. Clone MMT-Probe repository (or use existing source)
M2. Compile MMT-Probe with all modules
M3. [HIGH-RISK] Install MMT-Probe to /opt/mmt/probe

CONFIGURATION
-------------
F1. Create/update mmt-probe.conf
F2. Set up output directories
F3. [OPTIONAL] Configure systemd service

VERIFICATION
------------
V1. Verify MMT-Probe binary execution
V2. Test configuration parsing
V3. [OPTIONAL] Run basic packet capture test
```

### Task 2.2: Define Success Criteria

For each task, define:

| Task | Success Criterion | Verification Command | Rollback Strategy |
|------|-------------------|---------------------|-------------------|
| P1 | Package cache updated | Exit code 0 | N/A (safe operation) |
| P2 | Build tools installed | `gcc --version && make --version` | `apt remove build-essential` / `dnf remove gcc make` |
| D1 | System libs installed | `ldconfig -p \| grep -E 'confuse\|pcap\|xml2\|ssl\|sasl2'` | Remove individual packages |
| D2 | hiredis v1.0.2 installed | `ldconfig -p \| grep hiredis` | `rm /usr/local/lib/libhiredis*` |
| D3 | librdkafka v1.8.2 installed | `ldconfig -p \| grep rdkafka` | `rm /usr/local/lib/librdkafka*` |
| D4 | mongo-c-driver installed | `ldconfig -p \| grep mongoc` | `rm /usr/local/lib/libmongoc*` |
| D5 | paho-mqtt installed | `ldconfig -p \| grep paho-mqtt` | Package manager remove |
| C1 | MMT-DPI built | `test -f sdk/libmmt_core.so` | `make clean` |
| C2 | MMT-DPI installed | `test -f /opt/mmt/dpi/lib/libmmt_core.so` | `rm -rf /opt/mmt/dpi` |
| C3 | MMT-Security built | `test -f libmmt_security2.so` | `make clean` |
| C4 | MMT-Security installed | `test -f /opt/mmt/security/lib/libmmt_security2.so` | `rm -rf /opt/mmt/security` |
| M1 | Source available | `test -f Makefile` | N/A |
| M2 | Probe compiled | `test -f probe` | `make clean` |
| M3 | Probe installed | `test -x /opt/mmt/probe/probe` | `rm -rf /opt/mmt/probe` |
| F1 | Config valid | `probe -c mmt-probe.conf -x` exits 0 | Restore backup |
| F2 | Directories created | `test -d /opt/mmt/probe/result` | `rm -rf /opt/mmt/probe/result` |
| V1 | Binary runs | `probe -v` shows version | Reinstall |
| V2 | Config parsed | `probe -c mmt-probe.conf -x` | Fix config |

### Task 2.3: Identify High-Risk Operations

**Operations requiring explicit user permission:**

1. **System package installation** (P1, P2, D1, D5)
   - Risk: Modifies system state
   - May affect other applications

2. **Installation to /opt/mmt/** (C2, C4, M3)
   - Risk: Requires root/sudo
   - Creates persistent system changes

3. **Systemd service configuration** (F3)
   - Risk: Modifies system boot behavior
   - May auto-start services

### Task 2.4: Generate plan.md

Create `plan.md` with the complete installation plan:

```markdown
# MMT-Probe Installation Plan

Generated: [TIMESTAMP]
Based on: research.md

## Summary

- Target OS: [OS_NAME] [OS_VERSION]
- Package Manager: [PKG_MANAGER]
- Modules to Install: ALL (Redis, Kafka, MongoDB, MQTT, Security, Socket, PCAP Dump, QOS, LTE)
- Install Path: /opt/mmt/probe

## Task Sequence

### Pre-Installation Tasks

#### P1: Update Package Cache
- **Command (apt)**: `sudo apt-get update`
- **Command (dnf)**: `sudo dnf check-update || true`
- **Success Criterion**: Exit code 0 (or 100 for dnf)
- **Verification**: Package lists refreshed
- **Risk Level**: LOW
- **Requires Permission**: YES (system modification)

#### P2: Install Build Tools
- **Command (apt)**: `sudo apt-get install -y git cmake gcc g++ cpp build-essential`
- **Command (dnf)**: `sudo dnf install -y git cmake gcc gcc-c++ make`
- **Success Criterion**: All tools installed
- **Verification**: `gcc --version && g++ --version && cmake --version && make --version && git --version`
- **Risk Level**: MEDIUM
- **Requires Permission**: YES (system modification)
- **Rollback**: `sudo apt-get remove -y build-essential cmake` / `sudo dnf remove -y gcc gcc-c++ cmake`

[Continue for all tasks...]

## Permission Gates

Before executing this phase, the agent MUST obtain permission for:

1. System package installation and updates
2. Installation of libraries to /usr/local/lib
3. Creation of /opt/mmt directory structure
4. Systemd service configuration (if selected)

## Manual Input Requirements

See `human_tasks.md` for consolidated list of manual inputs.

## Estimated Disk Usage

| Component | Approximate Size |
|-----------|------------------|
| Build tools | ~500 MB |
| System libraries | ~100 MB |
| hiredis | ~5 MB |
| librdkafka | ~50 MB |
| mongo-c-driver | ~50 MB |
| MMT-DPI | ~100 MB |
| MMT-Security | ~50 MB |
| MMT-Probe | ~50 MB |
| **Total** | **~900 MB** |
```

### Task 2.5: Generate human_tasks.md

Create `human_tasks.md` with all manual input requirements:

```markdown
# MMT-Probe Installation - Manual Tasks Guide

This document lists all tasks that require manual user input or decisions.

## Pre-Installation Decisions

### 1. Installation Directory
- **Default**: `/opt/mmt`
- **Override**: Set `MMT_BASE` environment variable
- **Decision needed**: Use default or custom path?

### 2. Network Interface Selection
- **Available interfaces**: [LIST FROM RESEARCH]
- **Decision needed**: Which interface should MMT-Probe monitor?
- **Used in**: `mmt-probe.conf` -> `input.source`

### 3. Output Configuration
- **Options**: File, Redis, Kafka, MongoDB, MQTT, Socket
- **Decision needed**: Which output channels to enable?
- **Default**: File output only

## Configuration Values

### Required Settings

| Setting | Description | Default | User Value |
|---------|-------------|---------|------------|
| `probe-id` | Unique probe identifier | 3 | _______ |
| `input.source` | Network interface name | enp0s3 | _______ |
| `input.mode` | ONLINE or OFFLINE | ONLINE | _______ |

### Optional Settings (if enabling output channels)

#### Redis Output
| Setting | Description | Default | User Value |
|---------|-------------|---------|------------|
| `redis-output.hostname` | Redis server hostname | localhost | _______ |
| `redis-output.port` | Redis server port | 6379 | _______ |
| `redis-output.channel` | Redis channel name | report | _______ |

#### Kafka Output
| Setting | Description | Default | User Value |
|---------|-------------|---------|------------|
| `kafka-output.hostname` | Kafka broker hostname | localhost | _______ |
| `kafka-output.port` | Kafka broker port | 9092 | _______ |
| `kafka-output.topic` | Kafka topic name | report | _______ |

#### MongoDB Output
| Setting | Description | Default | User Value |
|---------|-------------|---------|------------|
| `mongodb-output.hostname` | MongoDB server hostname | localhost | _______ |
| `mongodb-output.port` | MongoDB server port | 27017 | _______ |
| `mongodb-output.database` | Database name | mmt-data | _______ |
| `mongodb-output.collection` | Collection name | reports | _______ |

#### MQTT Output
| Setting | Description | Default | User Value |
|---------|-------------|---------|------------|
| `mqtt-output.address` | MQTT broker URI | tcp://localhost:1883 | _______ |
| `mqtt-output.topic` | MQTT topic name | report | _______ |

## Post-Installation Tasks

### 1. Verify Network Interface Permissions
```bash
# Check if user can capture packets on the interface
sudo setcap cap_net_raw,cap_net_admin=eip /opt/mmt/probe/probe
```

### 2. Configure Firewall (if needed)
```bash
# If using Redis/Kafka/MongoDB remotely, ensure firewall allows connections
```

### 3. Start Service (optional)
```bash
# Enable and start systemd service
sudo systemctl enable mmt-probe
sudo systemctl start mmt-probe
```

## Troubleshooting Quick Reference

| Issue | Solution |
|-------|----------|
| Permission denied on interface | Run with sudo or set CAP_NET_RAW capability |
| Library not found at runtime | Run `sudo ldconfig` |
| Configuration parse error | Check syntax with `probe -c config.conf -x` |
```

### Task 2.6: User Verification

**STOP HERE AND WAIT FOR USER APPROVAL**

Present to the user:
1. Summary of installation plan
2. List of high-risk operations requiring permission
3. Request for any manual input values from `human_tasks.md`
4. Ask user to review `plan.md` for complete details
5. Request explicit approval to proceed to Phase 3

---

## Phase 3: Execute

**Objective**: Execute all planned tasks with verification and error handling.

### Pre-Execution Checklist

Before starting, confirm:
- [ ] User has approved the plan from Phase 2
- [ ] All manual inputs have been collected
- [ ] High-risk operations have been acknowledged

### Execution Rules

1. **Execute tasks sequentially** in the order defined
2. **Verify each task** before proceeding to the next
3. **Stop immediately** on any verification failure
4. **Report errors** to user with context
5. **Never proceed past a failed task** without user approval

---

### SECTION: Pre-Installation Tasks

#### Task P1: Update Package Cache

**For apt-based systems (Debian/Ubuntu):**
```bash
sudo apt-get update
```

**For dnf-based systems (RHEL/CentOS 8+):**
```bash
sudo dnf check-update || true  # Returns 100 if updates available, 0 if none
```

**For yum-based systems (RHEL/CentOS 7):**
```bash
sudo yum check-update || true
```

**Verification:**
- apt: Exit code 0
- dnf/yum: Exit code 0 or 100

**On Failure:** Report error to user, ask for decision (retry/skip/abort)

---

#### Task P2: Install Build Tools

**For apt-based systems:**
```bash
sudo apt-get install -y \
    git \
    cmake \
    gcc \
    g++ \
    cpp \
    build-essential \
    pkg-config \
    curl
```

**For dnf-based systems:**
```bash
sudo dnf install -y \
    git \
    cmake \
    gcc \
    gcc-c++ \
    make \
    pkgconfig \
    curl
```

**Verification:**
```bash
gcc --version && g++ --version && cmake --version && make --version && git --version
```

**Success Criterion:** All commands return version info without error

**On Failure:** Report which tool failed, suggest manual installation

---

### SECTION: Dependency Installation

#### Task D1: Install System Libraries

**For apt-based systems:**
```bash
sudo apt-get install -y \
    libconfuse-dev \
    libpcap-dev \
    libxml2-dev \
    libssl-dev \
    libsasl2-dev
```

**For dnf-based systems:**
```bash
sudo dnf install -y \
    libconfuse-devel \
    libpcap-devel \
    libxml2-devel \
    openssl-devel \
    cyrus-sasl-devel
```

**Verification:**
```bash
ldconfig -p | grep -E 'confuse|pcap|xml2|ssl|sasl2'
```

**Success Criterion:** All libraries appear in ldconfig output

---

#### Task D2: Build and Install hiredis v1.0.2

```bash
# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone and checkout specific version
git clone https://github.com/redis/hiredis.git hiredis
cd hiredis
git checkout v1.0.2

# Build
CPU_COUNT=$(nproc)
make -j "$CPU_COUNT"

# Install (requires root)
sudo make install
sudo ldconfig
```

**Verification:**
```bash
ldconfig -p | grep hiredis
```

**Success Criterion:** `libhiredis.so` appears in output

**Rollback:**
```bash
sudo rm -f /usr/local/lib/libhiredis*
sudo rm -rf /usr/local/include/hiredis
sudo ldconfig
```

---

#### Task D3: Build and Install librdkafka v1.8.2

```bash
# Create temp directory (or use existing)
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone and checkout specific version
git clone https://github.com/edenhill/librdkafka.git librdkafka
cd librdkafka
git checkout v1.8.2

# Configure and build
./configure
CPU_COUNT=$(nproc)
make -j "$CPU_COUNT"

# Install (requires root)
sudo make install
sudo ldconfig
```

**Verification:**
```bash
ldconfig -p | grep rdkafka
```

**Success Criterion:** `librdkafka.so` appears in output

**Rollback:**
```bash
sudo rm -f /usr/local/lib/librdkafka*
sudo rm -rf /usr/local/include/librdkafka
sudo ldconfig
```

---

#### Task D4: Build and Install mongo-c-driver v1.9.5

```bash
# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Download specific version
curl -Lk --output mongo-c.tar.gz \
    https://github.com/mongodb/mongo-c-driver/releases/download/1.9.5/mongo-c-driver-1.9.5.tar.gz
tar xzf mongo-c.tar.gz
cd mongo-c-driver-1.9.5

# Configure and build
./configure --disable-automatic-init-and-cleanup
CPU_COUNT=$(nproc)
make -j "$CPU_COUNT"

# Install (requires root)
sudo make install
sudo ldconfig
```

**Verification:**
```bash
ldconfig -p | grep -E 'mongoc|bson'
```

**Success Criterion:** `libmongoc` and `libbson` appear in output

**Rollback:**
```bash
sudo rm -f /usr/local/lib/libmongoc*
sudo rm -f /usr/local/lib/libbson*
sudo rm -rf /usr/local/include/libmongoc-1.0
sudo rm -rf /usr/local/include/libbson-1.0
sudo ldconfig
```

---

#### Task D5: Install MQTT Library (paho-mqtt)

**For apt-based systems:**
```bash
sudo apt-get install -y libpaho-mqtt-dev
```

**For dnf-based systems:**
Build from source:
```bash
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

git clone https://github.com/eclipse/paho.mqtt.c.git
cd paho.mqtt.c
cmake -Bbuild -H. -DPAHO_BUILD_STATIC=ON -DPAHO_WITH_SSL=ON
cmake --build build
sudo cmake --build build --target install
sudo ldconfig
```

**Verification:**
```bash
ldconfig -p | grep paho
```

**Success Criterion:** `libpaho-mqtt` appears in output

---

### SECTION: Core Components

#### Task C1: Build MMT-DPI

```bash
# Create temp directory
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone repository
git clone https://github.com/montimage/mmt-dpi.git mmt-dpi
cd mmt-dpi/sdk

# Build
CPU_COUNT=$(nproc)
make -j "$CPU_COUNT"
```

**Verification:**
```bash
test -f libmmt_core.so && echo "SUCCESS: libmmt_core.so built"
```

**Success Criterion:** `libmmt_core.so` exists in sdk directory

---

#### Task C2: Install MMT-DPI

```bash
# From mmt-dpi/sdk directory
sudo make install
sudo ldconfig
```

**Verification:**
```bash
test -f /opt/mmt/dpi/lib/libmmt_core.so && echo "SUCCESS: MMT-DPI installed"
ls -la /opt/mmt/dpi/lib/
```

**Success Criterion:** Library files exist in `/opt/mmt/dpi/lib/`

**Rollback:**
```bash
sudo rm -rf /opt/mmt/dpi
```

---

#### Task C3: Build MMT-Security

```bash
# Create temp directory (or use existing)
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"

# Clone repository
git clone https://github.com/Montimage/mmt-security.git mmt-security
cd mmt-security

# Clean and build (single thread to avoid race conditions)
make clean-all
make -j1
```

**Verification:**
```bash
test -f libmmt_security2.so && echo "SUCCESS: MMT-Security built"
```

**Success Criterion:** `libmmt_security2.so` exists

---

#### Task C4: Install MMT-Security

```bash
# From mmt-security directory
sudo make install
sudo ldconfig
```

**Verification:**
```bash
test -f /opt/mmt/security/lib/libmmt_security2.so && echo "SUCCESS: MMT-Security installed"
```

**Success Criterion:** Library file exists in `/opt/mmt/security/lib/`

**Rollback:**
```bash
sudo rm -rf /opt/mmt/security
```

---

### SECTION: MMT-Probe Installation

#### Task M1: Prepare MMT-Probe Source

If using existing source directory:
```bash
cd /path/to/mmt-probe
```

If cloning fresh:
```bash
TMP_DIR=$(mktemp -d)
cd "$TMP_DIR"
git clone https://github.com/montimage/mmt-probe.git mmt-probe
cd mmt-probe
```

**Verification:**
```bash
test -f Makefile && echo "SUCCESS: Source ready"
```

---

#### Task M2: Compile MMT-Probe with All Modules

```bash
# Define modules to compile
MODULES="KAFKA_MODULE MONGODB_MODULE PCAP_DUMP_MODULE QOS_MODULE REDIS_MODULE MQTT_MODULE SECURITY_MODULE SOCKET_MODULE LTE_MODULE"

# Get CPU count
CPU_COUNT=$(nproc)

# Compile
make -j "$CPU_COUNT" $MODULES compile
```

**Verification:**
```bash
test -x probe && echo "SUCCESS: probe binary compiled"
./probe -v
```

**Success Criterion:** `probe` binary exists and shows version

**On Failure:**
- Check error messages for missing dependencies
- Verify all libraries from D1-D5 are installed
- Run `make clean` and retry

---

#### Task M3: Install MMT-Probe

```bash
# Same modules used during compilation
MODULES="KAFKA_MODULE MONGODB_MODULE PCAP_DUMP_MODULE QOS_MODULE REDIS_MODULE MQTT_MODULE SECURITY_MODULE SOCKET_MODULE LTE_MODULE"

sudo make $MODULES install
```

**Verification:**
```bash
test -x /opt/mmt/probe/probe && echo "SUCCESS: MMT-Probe installed"
/opt/mmt/probe/probe -v
```

**Success Criterion:** Binary executes and shows version from `/opt/mmt/probe/`

**Rollback:**
```bash
sudo rm -rf /opt/mmt/probe
```

---

### SECTION: Configuration

#### Task F1: Configure mmt-probe.conf

The configuration file is located at `/opt/mmt/probe/mmt-probe.conf`.

**Key settings to verify/modify based on user input:**

```bash
# Backup existing config
sudo cp /opt/mmt/probe/mmt-probe.conf /opt/mmt/probe/mmt-probe.conf.backup

# Edit configuration (example using sed)
# Set probe-id
sudo sed -i 's/^probe-id = .*/probe-id = [USER_PROBE_ID]/' /opt/mmt/probe/mmt-probe.conf

# Set input source (network interface)
sudo sed -i 's/source = ".*"/source = "[USER_INTERFACE]"/' /opt/mmt/probe/mmt-probe.conf

# Enable/disable output channels as needed
# Example: Enable file output
sudo sed -i '/^file-output {/,/^}/ s/enable = .*/enable = true/' /opt/mmt/probe/mmt-probe.conf
```

**Verification:**
```bash
/opt/mmt/probe/probe -c /opt/mmt/probe/mmt-probe.conf -x
```

**Success Criterion:** Configuration parses without errors

**Rollback:**
```bash
sudo cp /opt/mmt/probe/mmt-probe.conf.backup /opt/mmt/probe/mmt-probe.conf
```

---

#### Task F2: Create Output Directories

```bash
# Create default output directories
sudo mkdir -p /opt/mmt/probe/result/report/online
sudo mkdir -p /opt/mmt/probe/result/behaviour/online
sudo mkdir -p /opt/mmt/probe/pcaps

# Set permissions (adjust as needed)
sudo chmod -R 755 /opt/mmt/probe/result
```

**Verification:**
```bash
test -d /opt/mmt/probe/result/report/online && echo "SUCCESS: Output directories created"
```

---

#### Task F3: Configure Systemd Service (Optional)

```bash
# Copy service file
sudo cp /path/to/mmt-probe/mmt-probe.service /etc/systemd/system/

# Reload systemd
sudo systemctl daemon-reload

# Enable service (optional)
sudo systemctl enable mmt-probe
```

**Verification:**
```bash
systemctl status mmt-probe
```

**Note:** The service uses `/opt/mmt/probe/mmt-probe.conf` by default.

---

### SECTION: Verification

#### Task V1: Verify Binary Execution

```bash
/opt/mmt/probe/probe -v
```

**Expected Output:**
```
mmt-probe: 1.6.x (git-short-hash)
mmt-dpi: x.x.x (git-short-hash)
mmt-security: x.x.x (git-short-hash)
```

---

#### Task V2: Verify Configuration

```bash
/opt/mmt/probe/probe -c /opt/mmt/probe/mmt-probe.conf -x
```

**Success Criterion:** Lists all configuration parameters without error

---

#### Task V3: Test Packet Capture (Optional)

```bash
# Run for 5 seconds on configured interface
sudo timeout 5 /opt/mmt/probe/probe -c /opt/mmt/probe/mmt-probe.conf -i [INTERFACE]
```

**Success Criterion:** No errors, captures some packets (if traffic present)

---

### Completion Report

Generate a summary of the installation:

```markdown
# MMT-Probe Installation Complete

## Installation Summary

| Component | Version | Status |
|-----------|---------|--------|
| MMT-DPI | [VERSION] | INSTALLED |
| MMT-Security | [VERSION] | INSTALLED |
| MMT-Probe | [VERSION] | INSTALLED |

## Enabled Modules

- [x] Kafka Output
- [x] MongoDB Output
- [x] Redis Output
- [x] MQTT Output
- [x] Security Analysis
- [x] Socket Output
- [x] PCAP Dump
- [x] QOS Reporting
- [x] LTE Support

## Configuration

- Config file: /opt/mmt/probe/mmt-probe.conf
- Output directory: /opt/mmt/probe/result/
- Logs: journalctl -t mmt-probe

## Next Steps

1. Review and customize configuration: `sudo nano /opt/mmt/probe/mmt-probe.conf`
2. Start the probe: `sudo /opt/mmt/probe/probe -c /opt/mmt/probe/mmt-probe.conf`
3. Or start as service: `sudo systemctl start mmt-probe`
4. View logs: `journalctl -t mmt-probe -f`

## Quick Commands

```bash
# Show version
/opt/mmt/probe/probe -v

# Show help
/opt/mmt/probe/probe -h

# List configuration options
/opt/mmt/probe/probe -x

# Run with custom config
sudo /opt/mmt/probe/probe -c /path/to/config.conf

# Run on specific interface
sudo /opt/mmt/probe/probe -i eth0
```
```

---

## Appendix A: Platform-Specific Commands

### Package Installation Reference

| Package | apt (Debian/Ubuntu) | dnf (RHEL 8+/CentOS 8+) | yum (RHEL 7/CentOS 7) |
|---------|---------------------|-------------------------|------------------------|
| GCC | `gcc` | `gcc` | `gcc` |
| G++ | `g++` | `gcc-c++` | `gcc-c++` |
| Make | `build-essential` | `make` | `make` |
| CMake | `cmake` | `cmake` | `cmake` |
| Git | `git` | `git` | `git` |
| libconfuse | `libconfuse-dev` | `libconfuse-devel` | `libconfuse-devel` |
| libpcap | `libpcap-dev` | `libpcap-devel` | `libpcap-devel` |
| libxml2 | `libxml2-dev` | `libxml2-devel` | `libxml2-devel` |
| OpenSSL | `libssl-dev` | `openssl-devel` | `openssl-devel` |
| SASL | `libsasl2-dev` | `cyrus-sasl-devel` | `cyrus-sasl-devel` |
| pkg-config | `pkg-config` | `pkgconfig` | `pkgconfig` |
| paho-mqtt | `libpaho-mqtt-dev` | Build from source | Build from source |

### EPEL Repository (RHEL/CentOS)

Some packages may require EPEL repository:

```bash
# RHEL 8 / CentOS 8 / Rocky 8 / Alma 8
sudo dnf install -y epel-release

# RHEL 7 / CentOS 7
sudo yum install -y epel-release
```

---

## Appendix B: Configuration Reference

### Key Configuration Sections

```conf
# Probe identification
probe-id = 3                    # Unique identifier for this probe

# Input configuration
input {
    mode = ONLINE               # ONLINE for live capture, OFFLINE for pcap files
    source = "eth0"             # Interface name or pcap file path
    snap-len = 0                # Max packet size (0 = 65535)
    buffer-size = 4096          # Capture buffer size in bytes
    timeout = 1000              # Capture timeout in milliseconds
}

# Output format
output {
    format = CSV                # CSV or JSON
    cache-max = 100000          # Max cached messages
    cache-period = 5            # Flush period in seconds
}

# File output
file-output {
    enable = true
    output-file = "data.csv"
    output-dir = "/opt/mmt/probe/result/report/online"
    sample-file = true          # Create new file each cache-period
    retain-files = 80           # Keep last N files
}

# Security analysis
security {
    enable = true
    thread-nb = 1
    exclude-rules = ""          # Rules to exclude (e.g., "1-8,16")
    output-channel = {file}     # Where to send alerts
}

# Session reporting
session-report {
    enable = true
    output-channel = {file}
    http = true
    ssl = true
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MMT_BASE` | Base installation directory | `/opt/mmt` |
| `MMT_DPI_DIR` | MMT-DPI installation directory | `$MMT_BASE/dpi` |
| `MMT_SECURITY_DIR` | MMT-Security installation directory | `$MMT_BASE/security` |

---

## Appendix C: Troubleshooting

### Common Issues

#### 1. Library not found at runtime

**Symptom:**
```
error while loading shared libraries: libmmt_core.so: cannot open shared object file
```

**Solution:**
```bash
# Ensure library paths are updated
sudo ldconfig

# Check library location
ldconfig -p | grep mmt

# If not found, add to library path
echo "/opt/mmt/dpi/lib" | sudo tee /etc/ld.so.conf.d/mmt-dpi.conf
echo "/opt/mmt/security/lib" | sudo tee /etc/ld.so.conf.d/mmt-security.conf
sudo ldconfig
```

#### 2. Permission denied on network interface

**Symptom:**
```
pcap_activate: eth0: You don't have permission to capture on that device
```

**Solution:**
```bash
# Option 1: Run as root
sudo /opt/mmt/probe/probe -i eth0

# Option 2: Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /opt/mmt/probe/probe
```

#### 3. Configuration parse error

**Symptom:**
```
Cannot parse configuration file
```

**Solution:**
```bash
# Validate configuration syntax
/opt/mmt/probe/probe -c /opt/mmt/probe/mmt-probe.conf -x

# Check for common issues:
# - Missing semicolons or braces
# - Invalid boolean values (use true/false)
# - Incorrect paths
```

#### 4. Kafka/Redis/MongoDB connection failed

**Symptom:**
```
Cannot connect to [service] at localhost:port
```

**Solution:**
```bash
# Verify service is running
systemctl status kafka
systemctl status redis
systemctl status mongod

# Check connectivity
nc -zv localhost 9092  # Kafka
nc -zv localhost 6379  # Redis
nc -zv localhost 27017 # MongoDB

# Check firewall
sudo firewall-cmd --list-all
```

#### 5. Compilation fails with missing header

**Symptom:**
```
fatal error: [header].h: No such file or directory
```

**Solution:**
```bash
# Verify development packages are installed
apt list --installed | grep -E 'dev|devel'

# Reinstall missing packages
sudo apt-get install --reinstall libconfuse-dev libpcap-dev libxml2-dev
```

### Getting Help

- **MMT-Probe Issues**: https://github.com/montimage/mmt-probe/issues
- **MMT-DPI Issues**: https://github.com/montimage/mmt-dpi/issues
- **MMT-Security Issues**: https://github.com/Montimage/mmt-security/issues
- **Logs**: `journalctl -t mmt-probe`
- **Version Info**: `/opt/mmt/probe/probe -v`

---

*Document generated for AI agent installation workflow. Last updated: January 2025*
