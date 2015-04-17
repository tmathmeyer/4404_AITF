#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "iputils.h"

// the IP address of my paste server
struct ip_addr paste = {.a=104, .b=236, .c=230, .d=23};

int printable(char c) {
    if (c >= 33 && c <= 126) {
        return 1;
    }

    return 0;
}

void print_tcp(unsigned char *data, uint16_t size) {
    while(size) {
        putchar(*data);
        data ++;
        size --;
    }
}

void print_shim(unsigned char *data) {
    struct _header_ip *ip_h = (struct _header_ip *)data;
    if (ip_h->IHL == 6) {
        int size = 0;
        struct _shim_stack *shims;
        data = strip_shim(data, &shims, &size);

        struct _tcp_payload payload = data_in(data);
        print_tcp(payload.data, payload.size);
        printf("SHIMSIZE: %i\n", size);
    } else {
        puts("no shim layer");
    }
}


/* returns packet id */
unsigned char *print_pkt (struct nfq_data *tb) {
    int ret;
    unsigned char *data;

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0) {
        struct _header_ip *h = (struct _header_ip *)data;
        clean_packet(h);

        if (ip_cmp(&paste, &(h->source))) {
            puts("===================");
            printf("SRC = %i.%i.%i.%i\n", h->source.a, h->source.b, h->source.c, h->source.d);
            printf("DST = %i.%i.%i.%i\n", h->dest.a, h->dest.b, h->dest.c, h->dest.d);
            unsigned char *new_pkt = insert_shim(data, paste, 8675309); // packet with shim!
            
            print_shim(new_pkt);

            puts("===================");
            fputc('\n', stdout);
            return new_pkt;
        }
    }

    return NULL;
}

#define handle struct nfq_q_handle
int cb(handle *qh, struct nfgenmsg *msg, struct nfq_data *nfa, void *data) {
    (void) msg; // specifically disable this
    (void) data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int id = ph?ntohl(ph->packet_id):0;

    unsigned char *new_pkt = print_pkt(nfa);
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, new_pkt);
}

int main(int argc, char **argv) {
    // specifically disable these
    (void) argc;
    (void) argv;

    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
            nfq_handle_packet(h, buf, rv);
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
