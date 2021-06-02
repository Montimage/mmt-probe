This folder contains implementation of getting data from a stream that is either a socket or a file.
Normally MMT-Probe get data that is pcap packets that are network packets. The packets are captured either using libpcap or DPDK.

The implementation in this folder allow MMT-Probe to receive data from a stream that is a socket or from a file.
The data in the stream is separated by '\n' character. Consequently, each data packet is a "line" in the stream.