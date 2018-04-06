/**
 * pcap_dump aims to provide some basic functions to write a packet data into a pcap file
 */
#ifndef PCAP_DUMP_H_
#define PCAP_DUMP_H_
#include <stdint.h>
#include <sys/time.h>
#include <stdbool.h>

typedef struct pcap_dump_struct pcap_dump_t;

/**
 * Create a new pcap file with given linktype, timezone and snaplen
 * - write a pcap header to a new file. Called by openPcapFile. Shouldn't be used outside pcap_dump.c
 * @param  path     path to the pcap file
 * @param  linktype link type
 * @param  thiszone timezone
 * @param  snaplen  snaplen
 * @return          pointer points to the file
 */
pcap_dump_t* pcap_dump_create(const char * path, int linktype, int thiszone, uint16_t snaplen);

/**
 * Write a buffer into a pcap file with given timestamp
 * 
 * @param  fd  points to the pcap file
 * @param  buf packet data
 * @param  len length of packet
 * @param  tv  timestamp
 * @return true if write successfully to file, otherwise false (such as, not enough space, ...)
 */
bool pcap_dump_write(pcap_dump_t *, const char * buf, uint16_t len, uint16_t caplen, const struct timeval *tv);
/**
 * Close a pcap file after finish writing
 * @param fd points to pcap file
 */
void pcap_dump_release(pcap_dump_t *);

#endif //end of pcap_dump.h
