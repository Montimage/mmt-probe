# 20180530
- Add `TCP_PAYLOAD_DUMP` option - which allow the MMT-Probe to dump the TCP payload with the handling of tcp segmentation by `mmt-reassembly library`
To compile the probe with this option: `make TCP_PAYLOAD_DUMP=1`