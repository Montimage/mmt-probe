#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include "pcap_dump.h"

int pd_write_header(int fd, int linktype, int thiszone, int snaplen) {
    struct pd_pcap_file_header hdr;
    hdr.magic = 0xa1b2c3d4;
    hdr.version_major = 2;
    hdr.version_minor = 4;
    hdr.thiszone = thiszone;
    hdr.snaplen = snaplen;
    hdr.sigfigs = 0;
    hdr.linktype = linktype;
    int left = sizeof(hdr), ret;
    char * ptr = (char*) &hdr;
    while (left > 0) {
        ret = write(fd, ptr, left);
        left -= ret;
        ptr += ret;
    }
    fsync(fd);
    return 0;
}

int pd_write(int fd, char * buf, int len, struct timeval tv) {
    struct pd_pcap_pkthdr h;
    // char mem[65535];
    if (len > 65535) {
        len = 65535;
    }
    int left = sizeof(h), ret;
    h.ts.tv_sec = (uint32_t)tv.tv_sec;
    h.ts.tv_usec = (uint32_t)tv.tv_usec;

    h.caplen = len;
    h.len = len;

    char * ptr = (char*) &h;
    while (left > 0) {
        ret = write(fd, ptr, left);
        left -= ret;
        ptr += ret;

    }

    left = len;
    while (left > 0) {
        ret = write(fd, buf, left);
        buf += ret;
        left -= ret;

    }
    return 0;
}

int pd_create(const char * path, int linktype, int thiszone, int snaplen) {
    int fd;
    fd = open(path, O_CREAT | O_WRONLY | O_APPEND, S_IRUSR | S_IWUSR);
    if (fd == -1)return fd;
    int pos = lseek(fd, 0, SEEK_END);
    if (pos == -1)return -1;
    if (pos == 0) {
        pd_write_header(fd, linktype, thiszone, snaplen);
    }
    return fd;
}

int pd_open(const char * path) {
    return pd_create(path, 1, 0, 65535);
}

void pd_close(int fd) {
    close(fd);
}