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
struct ip_addr googl = {.a=8, .b=8, .c=8, .d=8};
struct ip_addr tests = {.a=7, .b=7, .c=7, .d=7};
struct ip_addr local = {.a=192, .b=168, .c=1, .d=195};

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

void print_tcp_header(void *tcp) {
    struct _header_ip *iph = (struct _header_ip *)tcp;
    printf("IHL: %i\n", iph->IHL);
    printf("LEN: %i\n", iph->total_length);
    printf("CHK: %x\n", iph->checksum);
    if (iph->IHL > 5) {
        printf("SHM: %i\n", iph->shim_size_opt);
    }
}

void print_ip(struct ip_addr ip) {
    printf("%i.%i.%i.%i\n", ip.a, ip.b, ip.c, ip.d);
}

void print_shim_stack_layer(struct _shim_stack *shims, int size) {
    while(size --> 0) {
        print_ip((shims+size)->shim_ip);
        printf("SHM-RND: %lu\n", *( (uint64_t *) (&(shims+size)->hash)));
    }
}

void print_shim(unsigned char *data) {
    struct _tcp_payload payload = data_in(data);
    print_tcp(payload.data, payload.size);
    print_tcp_header(data);


    data = insert_shim(data, paste, 2222);
    data = insert_shim(data, googl, 3333);
    data = insert_shim(data, local, 1234);
    data = insert_shim(data, tests, 5678);
    
    struct _header_ip *ip_h = (struct _header_ip *)data;
    if (ip_h->IHL == 6) {
        int size = 0;
        struct _shim_stack *shims;
        data = strip_shim(data, &shims, &size);
        
        
        puts("------------");
        print_shim_stack_layer(shims, size);
        puts("------------");


        print_tcp_header(data);
        struct _tcp_payload payload = data_in(data);
        print_tcp(payload.data, payload.size);
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

        if (ip_cmp(&paste, &(h->source)) && h->total_length>80 && h->total_length<200) {
            puts("===================");
            printf("SRC = ");
            print_ip(h->source);
            printf("DST = ");
            print_ip(h->dest);
            
            print_shim(data);

            puts("===================");
            fputc('\n', stdout);
            return data;
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
