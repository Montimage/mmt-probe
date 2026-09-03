# Development Guide

This guide covers setting up a development environment for MMT-Probe.

## Prerequisites

| Dependency | Version | Purpose |
|-----------|---------|---------|
| GCC | 4.9+ | C compiler |
| GNU Make | 3.81+ | Build system |
| libconfuse | any | Configuration file parsing |
| MMT-DPI | latest | Deep packet inspection library |
| libpcap | any | Packet capture (default mode) |

### Install Build Dependencies (Ubuntu/Debian)

```bash
sudo apt-get update
sudo apt-get install build-essential libconfuse-dev libpcap-dev
```

### Install MMT-DPI

Follow the instructions at [MMT-DPI](https://github.com/montimage/mmt-dpi). By default, MMT-DPI installs to `/opt/mmt/dpi`.

## Building

### Basic Build

```bash
make
```

### Debug Build

Enables `-g -O0` flags for gdb debugging:

```bash
make DEBUG compile
```

### With Optional Modules

```bash
# All modules
make ALL_MODULES compile

# Specific modules
make SECURITY_MODULE KAFKA_MODULE MQTT_MODULE compile
```

### Custom Install Path

```bash
make MMT_BASE=/path/to/mmt compile
```

### Static Linking

Embed MMT-DPI and other libraries into the binary:

```bash
make STATIC_LINK compile
```

## Project Layout

- `src/main.c` -- Entry point, argument parsing, process forking
- `src/configure.c` -- Configuration file parsing using libconfuse
- `src/configure_override.c` -- Runtime configuration override via `-X` flags
- `src/worker.c` -- Worker thread lifecycle management
- `src/context.h` -- Global context and shared data structures
- `src/lib/` -- Utility libraries (hashing, string building, memory management, logging)
- `src/modules/` -- Feature modules (DPI, LPI, output, security, capture)
- `mk/` -- Makefile fragments for modular build configuration

## Architecture Overview

MMT-Probe runs as three processes:

1. **Monitor process** -- Root process; spawns and monitors children, restarts them on crash
2. **Processing process** -- Main packet analysis; runs worker threads for DPI/LPI
3. **Control process** -- Optional; listens on a UNIX socket for dynamic reconfiguration commands

See [docs/architecture.md](architecture.md) for the detailed process diagram.

## Debugging

### With GDB

```bash
make DEBUG compile
sudo gdb ./probe
(gdb) run -t test/UA-Exp01.pcap -c mmt-probe.conf
```

### With Valgrind

```bash
make VALGRIND compile
sudo valgrind --leak-check=full ./probe -t test/UA-Exp01.pcap
```

### Logging

MMT-Probe logs via `syslog`. View logs with:

```bash
journalctl -t mmt-probe
```

## Adding a New Module

1. Create a directory under `src/modules/<your-module>/`
2. Add source files following existing module patterns
3. Register the module in `mk/modules.mk` with a compile flag (e.g., `YOUR_MODULE`)
4. Add conditional compilation in the Makefile
5. Update documentation

## Code Conventions

- Use tabs for indentation
- Follow `snake_case` for functions and variables
- Use `UPPER_SNAKE_CASE` for macros and constants
- Check all memory allocations for `NULL`
- Free resources in all exit paths
- Use the logging macros from `src/lib/log.h`
