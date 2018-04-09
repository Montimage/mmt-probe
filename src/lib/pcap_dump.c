#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include "pcap_dump.h"

#include "memory.h"

struct pcap_dump_struct{
	FILE *file;
};

struct pd_timeval {
	uint32_t tv_sec;     /* seconds */
	uint32_t tv_usec;    /* microseconds */
};

//see: https://wiki.wireshark.org/Development/LibpcapFileFormat
struct pd_pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;     /* gmt to local correction */
	uint32_t sigfigs;     /* accuracy of timestamps */
	uint32_t snaplen;     /* max length saved portion of each pkt */
	uint32_t linktype;    /* data link type (LINKTYPE_*) */
};

struct pd_pcap_pkthdr {
	struct pd_timeval ts;  /* time stamp using 32 bits fields */
	uint32_t caplen;       /* length of portion present */
	uint32_t len;          /* length this packet (off wire) */
};


static inline void _write_header(pcap_dump_t *fd, int linktype, int thiszone, int snaplen) {
    struct pd_pcap_file_header hdr;
    hdr.magic = 0xa1b2c3d4; //
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;

    fwrite( &hdr, sizeof( hdr ), 1, fd->file );
}

bool pcap_dump_write(pcap_dump_t *fd, const char * buf, uint16_t len, uint16_t caplen, const struct timeval *tv) {
    struct pd_pcap_pkthdr h;

    h.ts.tv_sec  = (uint32_t)tv->tv_sec;
    h.ts.tv_usec = (uint32_t)tv->tv_usec;

    h.caplen = caplen;
    h.len = len;

    //write header
    if( fwrite( &h, sizeof( h ), 1, fd->file ) != 1 )
    	return false;

    //write packet data
    if( fwrite( buf, sizeof( char ), caplen, fd->file ) != caplen)
    	return false;

    return true;
}

pcap_dump_t * pcap_dump_create(const char * path, int linktype, int thiszone, uint16_t snaplen) {
	//open file for writing
    FILE *file = fopen( path, "w" );
    if (file == NULL)
    	return NULL;

    pcap_dump_t *ret = mmt_alloc( sizeof (pcap_dump_t ));
    ret->file = file;

    //header of pcap file
    _write_header( ret, linktype, thiszone, snaplen);

    return ret;
}

void pcap_dump_release(pcap_dump_t *handler) {
	if( handler->file )
		fclose( handler->file );
    mmt_probe_free( handler );
}
