#include <stdio.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>        /* for NF_ACCEPT */

#include <libnetfilter_queue/libnetfilter_queue.h>

int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data) {
  int id;
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
  if (ph) {
    id = ntohl(ph->packet_id);
  }

  nfq_set_verdict (qh, id, NF_ACCEPT, 0, data);
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


