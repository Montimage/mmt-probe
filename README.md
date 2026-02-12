# MMT Probe


This repository contains source code of MMT-Probe that analyses online or offline network traffic.

- [Compilation and Installation](./docs/installation.md)
- [Configuration](./docs/configuration.md)

## Optional Modules

The following modules are **not included in the default build**. They must be explicitly enabled at compile time.

### Kafka Input (Traffic Consumer)

This module allows MMT-Probe to **consume traffic data from a Kafka topic** instead of capturing from a network interface or reading from a pcap file. It is mutually exclusive with the PCAP, DPDK, and Stream capture modes.

**Dependencies:** `librdkafka` (if `KAFKA_MODULE` is already enabled for kafka-output, the library is already linked).

**Build:**

```bash
# Kafka input only (no kafka-output)
make KAFKA_INPUT=1

# Kafka input + kafka output (shares librdkafka)
make KAFKA_INPUT=1 KAFKA_MODULE=1
```

> **Note:** Kafka input does not support multi-threading. Set `thread-nb=0` in `mmt-probe.conf`.

**Configuration** (in `mmt-probe.conf`):

```
kafka-input {
    enable = true
    hostname = "localhost"
    port = 9092
    topic = "traffic-data"
    group-id = "mmt-probe-consumer"
    offset-reset = "earliest"   # "earliest" or "latest"
    # Optional SASL authentication:
    # username = ""
    # password = ""
}
```

Parameters can also be overridden from the command line:

```bash
./mmt-probe -X kafka-input.enable=true -X kafka-input.hostname=broker1 -X kafka-input.topic=my-traffic
```

### Stream File Input

This module allows MMT-Probe to **read and analyse data from a text file, line by line**, instead of capturing from a network interface. Each line is treated as one message/packet. It is mutually exclusive with the PCAP, DPDK, and Kafka input capture modes.

This is useful for analysing pre-recorded protocol data (e.g., OCPP messages, CICFlow CSV) that has been stored as text rather than as a pcap capture.

**Dependencies:** None (beyond standard C library).

**Build:**

```bash
make STREAM_CAPTURE=1
```

> **Note:** Stream capture only supports offline analysis and does not support multi-threading. Set `thread-nb=0` and `input.mode = OFFLINE` in `mmt-probe.conf`.

**Configuration** (in `mmt-probe.conf`):

```
input {
    mode = OFFLINE
    source = "/path/to/data-file.txt"
}
```

### STIX 2.1 Alert Format

This module formats security alerts as **STIX 2.1 bundles** (JSON). When enabled, alerts from `mmt-security` that match a known rule are automatically wrapped into a STIX bundle containing Sighting, Indicator, Attack Pattern, and Observed Data objects with MITRE ATT&CK references.

Rules without a STIX mapping fall back to the standard CSV/JSON output format.

**Dependencies:** `libuuid` (for UUID generation).

**Build:**

```bash
make STIX_FORMAT=1

# Typically combined with security and an output module:
make SECURITY_MODULE=1 KAFKA_MODULE=1 STIX_FORMAT=1
```

**Supported attack rules** (extensible in `src/modules/output/stix_alert.c`):

| Rule ID | Attack Name | MITRE ATT&CK |
|---------|-------------|---------------|
| 201 | OCPP DoS Flooding Heartbeat | T1498 |
| 202 | OCPP Charging Profile FDI | T1565 |
| 203 | PHP Insecure Intrusion | T1190 |
| 204 | SMB Intrusion | T1003 |
| 206 | PACS Server DDoS | T1498 |
| 207 | Lockbit Execution | — |
| 210 | RDP Intrusion | T1110 |
| 211 | SSH Intrusion | T1078 |

To add new attack types, append entries to the `attack_info_list[]` table in `src/modules/output/stix_alert.c`. To add known asset UUID mappings, edit the `asset_list[]` table in the same file.

# 
![](https://komarev.com/ghpvc/?username=montimage-probe&style=flat-square&label=Page+Views)
