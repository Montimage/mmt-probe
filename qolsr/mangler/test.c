#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct olsr_pkt_hdr_struct {
  uint16_t len;
  uint16_t seqnb;
}olsr_pkt_hdr_t;

typedef struct olsr_hello_struct {
  uint8_t type;
  uint8_t validity;
  uint16_t len;
  uint32_t orig;
  uint8_t ttl;
  uint8_t hopcount;
  uint16_t seqnb;
  uint16_t reserved;
  uint8_t period;
  uint8_t will;
}olsr_hello_t;

typedef struct olsr_neighbor_lnk_struct {
	uint32_t neighbor;
	uint8_t fwd_signal;
	uint8_t rcv_signal;
	uint8_t  interface;
	uint8_t  reserve;
}olsr_neighbor_lnk_t;

int format_mangle(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *user) {
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
  if (ph) {
    id = ntohl(ph->packet_id);
  }
  // Print the payload; in copy meta mode, only headers will be included;
  // in copy packet mode, whole packet will be returned.
  char *pktData;
  int len = nfq_get_payload(nfad, &pktData);
  if (len) {
    printf("data[%u]: '", len);
    int i;
    for (i = 0; i < len; i++) {
      if (isprint(pktData[i]))
        printf("%c", pktData[i]);
      else printf(" ");
    }
    printf("'\n");
    // end data found
  }
//change the packet data, offset 26 udp checksum and 34 hello length
  unsigned short * cksum = (unsigned short *) &pktData[26];
  printf("checksum = %hu\n", *cksum);
  *cksum = 0;

  unsigned short * plen = (unsigned short *) &pktData[34];
  *plen = *plen + 8;

  return  nfq_set_verdict (qh, id, NF_ACCEPT, len, pktData);
}

int olsr_mangle(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *user) {
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
  if (ph) {
    id = ntohl(ph->packet_id);
  }
  // Print the payload; in copy meta mode, only headers will be included;
  // in copy packet mode, whole packet will be returned.
  char *pktData;
  int len = nfq_get_payload(nfad, &pktData);

  char newData[500];
  char * data = &pktData[28];

    int format = 0;
    olsr_pkt_hdr_t * pkt = (olsr_pkt_hdr_t *) data;
    //validate format
    uint16_t offset = 4;
    uint16_t pkt_len = ntohs(pkt->len); //ignor the header len
    if( ( pkt_len < 4 ) || (pkt_len % 4) != 0) {
      format = 1;
      return  nfq_set_verdict (qh, id, NF_ACCEPT, 0, NULL);
    }

    pkt_len -= 4;

    while(pkt_len > 0) {
        olsr_hello_t * hello = (olsr_hello_t *) (& data[offset]);
        uint16_t hello_len = ntohs(hello->len);

        if( ( pkt_len < hello_len ) || ( hello_len < 16 ) || (hello_len % 4) != 0) {
          format = 1;
          return  nfq_set_verdict (qh, id, NF_ACCEPT, 0, NULL);
        }
//jeevan hello->type == 201 to hello->type == 1 (qolsr)
        if(hello->type == 1) {

          int hello_offset = 16;
          hello_len -= hello_offset;
          while(hello_len > 0) {
            olsr_hello_t * hello_pkt = (olsr_hello_t *) (&data[offset + hello_offset]);
            if( ( hello_len < ntohs(hello_pkt->len) ) || ( ntohs(hello_pkt->len) < 12 ) || ((ntohs(hello_pkt->len) - 4) % 8) != 0) {
              format = 1;
              return  nfq_set_verdict (qh, id, NF_ACCEPT, 0, NULL);
            }

            if(hello_pkt->type == 6 || hello_pkt->type == 10) {
              int nb_neighbors = (ntohs(hello_pkt->len) - 4)/8;
              int count = 0;
              memcpy(newData, pktData, 28 + offset + hello_offset + 4);
//jeevan change user data by adding fake neighbour address, lq and nlq
              olsr_neighbor_lnk_t fakelink = {0};
              fakelink.neighbor = ntohl(0xC0A8C805);
              fakelink.fwd_signal = 101;
              fakelink.rcv_signal = 102;
              fakelink.interface =0;
              fakelink.reserve = 0;


              memcpy(&newData[28 + offset + hello_offset + 4], &fakelink, 8);
              
              memcpy(&newData[28 + offset + hello_offset + 4 + 8], &pktData[28 + offset + hello_offset + 4], len - (28 + offset + hello_offset + 4));

              unsigned short * cksum = (unsigned short *) &newData[26];
              *cksum = 0;

              return  nfq_set_verdict (qh, id, NF_ACCEPT, len + 8, newData);
            }

            hello_offset += ntohs(hello_pkt->len);
            hello_len -= ntohs(hello_pkt->len);
          }
        }
        offset += ntohs(hello->len);
        pkt_len -= ntohs(hello->len);
    }
}

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
  if (ph) {
    id = ntohl(ph->packet_id);
  }
//jeevan radomly select the packets
  int r = rand() % 20;
  if(r < 5) {
    format_mangle(qh, nfmsg, nfad, data);
  }else if(r < 10) {
    olsr_mangle(qh, nfmsg, nfad, data);
  }else {
    nfq_set_verdict (qh, id, NF_ACCEPT, 0, data);
  }
}

int main() {
  struct nfq_handle * h = nfq_open();
  char buf[2000] = {0};

  if (!h) {
    fprintf(stderr, "error during nfq_open()\n");
    exit(1);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");

  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  printf("binding nfnetlink_queue as nf_queue handler for AF_INET %u\n", AF_INET);

  if (nfq_bind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_bind_pf()\n");
    exit(1);
  }

  printf("binding this socket to queue '0'\n");
  struct nfq_q_handle * qh = nfq_create_queue(h,  0, &cb, NULL);
  if (!qh) {
    fprintf(stderr, "error during nfq_create_queue()\n");
    exit(1);
  }

  printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    fprintf(stderr, "can't set packet_copy mode\n");
    exit(1);
  }

  int fd = nfq_fd(h);
  int rv;
  while ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
    printf("pkt received\n");
    nfq_handle_packet(h, buf, rv);
  }

  printf("unbinding existing nf_queue handler for AF_INET (if any)\n");

  if (nfq_unbind_pf(h, AF_INET) < 0) {
    fprintf(stderr, "error during nfq_unbind_pf()\n");
    exit(1);
  }

  if (nfq_close(h) < 0) {
    fprintf(stderr, "error during nfq_close()\n");
    exit(1);
  }

  return 0;
}


