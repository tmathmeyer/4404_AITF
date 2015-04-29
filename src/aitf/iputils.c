#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>
#include "iputils.h"

int ip_cmp(struct ip_addr *a, struct ip_addr *b) {
    if (a == b) {
        return 1;
    }
    if (!a || !b) {
        return 0;
    }
    return (a->a==b->a) && (a->b==b->b)
        && (a->c==b->c) && (a->d==b->d);
}

void clean_packet(struct _header_ip *h) {
    h->total_length = ntohs(h->total_length);
}

void fix_packet(struct _header_ip *h) {
    h->total_length = htons(h->total_length);
}

struct _tcp_payload data_in(unsigned char *raw) {
    struct _header_ip *h = (struct _header_ip *)raw;
    uint8_t ip_header_size = h->IHL * 4;
    uint32_t ip_payload_size = htons(h->total_length) - ip_header_size;
    raw += ip_header_size; // remove IP Header
    struct _tcp *tcp = (struct _tcp *)raw; // should check if tcp or udp later

    uint8_t tcp_header_size = tcp->offset * 4;
    struct _tcp_payload payload;
    payload.data = raw+tcp_header_size;
    payload.size = ip_payload_size - tcp_header_size;
    return payload;
}


void print_bytes(struct _header_ip *header) {
    uint32_t bytec = htons(header->total_length);
    uint32_t i = 0;
    unsigned char *bytes = (unsigned char *)header;
    while (i < bytec) {
        printf("%02X ",bytes[i]);
        i++;
        if (i%16 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}



uchar *insert_shim(uchar *orig, struct ip_addr addr, uint64_t rando, uint32_t *size) {
    struct _header_ip *ip = (struct _header_ip *)orig;
    struct _shim_stack shim;
    shim.hash = rando;
    shim.hash_extra = 42;
    shim.shim_ip = addr;

    *size = ntohs(ip->total_length);
    size_t packet_increase = 12;
    if (ip->protocol != AITF) {
        packet_increase = 16;
    }


    struct _header_ip *new_ip = malloc(*size + packet_increase);

    unsigned char *header = (unsigned char *)new_ip;
    unsigned char *shimla = header + sizeof(struct _header_ip);
    unsigned char *datalo = shimla + sizeof(struct _shim_stack);

    size_t shimsize = sizeof(struct _shim_stack);
    size_t headsize = ip->IHL * 4; 
    size_t bodysize = *size - headsize;

    memcpy(datalo, orig+headsize, bodysize); // copy in the body
    memcpy(shimla, &shim, shimsize); // copy the shimsize in too
    memcpy(header, orig, headsize); // copy the header in

    *size += packet_increase;

    new_ip->total_length = htons(*size); // write the size in
    if (ip->protocol != AITF) {
        new_ip->shim_size_opt = 1;
    } else {
        new_ip->shim_size_opt += 1;
    }


    if (new_ip->protocol != AITF) {
        new_ip->original_protocol = new_ip->protocol;
    }


    new_ip->protocol = AITF;
    new_ip->IHL = 6;

    recompute_checksum(header);


    return header;
}

uchar *strip_shim(uchar *data, struct _shim_stack **location, uint8_t *sl, uint8_t max, uint32_t *size) {
    (void)max;

    struct _header_ip *ip = (struct _header_ip *)data;
    *sl = ip->shim_size_opt;
    uint32_t mem = *sl * sizeof(struct _shim_stack);
    *location = malloc(mem);
    memcpy(*location, data+24, mem);


    *size = ntohs(ip->total_length);

    struct _header_ip *new_ip = malloc(*size - 16);
    unsigned char *header = (uchar *)new_ip;
    unsigned char *body = header + 20;

    size_t header_size = 20;
    size_t body_size = *size - 36;

    memcpy(header, data, header_size);
    memcpy(body, data+36, body_size);

    *size -= 16;

    new_ip->total_length = htons(*size);
    new_ip->IHL = 5;
    new_ip->protocol = ip->original_protocol;


    recompute_checksum(header);
    return header;
}








unsigned short ip_sum_calc(unsigned short len_ip_header, unsigned short *buff){
    long sum = 0;
    int i = 0;

    for (i=0;i<len_ip_header/2;i++){
        sum += ntohs(buff[i]);
    }

    while (sum >> 16){
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    sum = ~sum;

    return htons(((unsigned short) sum));
}


void recompute_checksum(unsigned char *data) {
    int len = ((struct _header_ip *)data)->IHL * 4;
    ((struct _header_ip *)data)->checksum = (uint16_t)0;
    ((struct _header_ip *)data)->checksum = ip_sum_calc(len, (unsigned short *)data);
}










// printing utilities
int ip_len(struct ip_addr ip) {
    int ct = 7;
    if (ip.a > 100) ct++;
    if (ip.b > 100) ct++;
    if (ip.c > 100) ct++;
    if (ip.d > 100) ct++;

    if (ip.a > 10) ct++;
    if (ip.b > 10) ct++;
    if (ip.c > 10) ct++;
    if (ip.d > 10) ct++;

    return ct;
}

void pretty_print_packet(struct _header_ip *ip) {
    int srclen = 31 - (ip_len(ip->source) + 4),
        destlen = 31 - (ip_len(ip->dest) + 5);

    printf("╔═══╤═══╤═══════╤═══════════════╗\n");
    printf("║%3i│%3i│%7i│%15i║\n", ip->version, ip->IHL, ip->serv_type, ip->total_length);
    printf("╟───┴───┴───────┼───────────────╢\n");
    printf("║%15i│%15i║\n", ip->identification, ip->flags);
    printf("╟───────┬───────┼───────────────╢\n");
    printf("║%7i│%7i│%15i║\n", ip->ttl, ip->protocol, ip->checksum);
    printf("╟───────┴───────┴───────────────╢\n");
    printf("║%*cSRC:", srclen/2, ' '); print_ip(ip->source); printf("%*c║\n", srclen-(srclen/2),' ');
    printf("╟───────────────────────────────╢\n");
    printf("║%*cDEST:", destlen/2, ' '); print_ip(ip->dest); printf("%*c║\n", destlen-(destlen/2),' ');
    printf("╚═══════════════════════════════╝\n");

}

void print_ip(struct ip_addr ip) {
    printf("%i.%i.%i.%i", ip.a, ip.b, ip.c, ip.d);
}

void fancy_print_packet(struct _header_ip *ip) {
    printf("IHL: %i\n", ip->IHL);
    printf("VER: %i\n", ip->version);
    printf("TYP: %i\n", ip->serv_type);
    printf("LEN: %i\n", ip->total_length);
    printf("IDT: %i\n", ip->identification);
    printf("FLG: %i\n", ip->flags);
    printf("FRG: %x\n", ip->frag_offset);
    printf("TTL: %i\n", ip->ttl);
    printf("PRO: %i\n", ip->protocol);
    printf("CHK: %i\n", ip->checksum);
    printf("SRC: ");print_ip(ip->source);puts("");
    printf("DST: ");print_ip(ip->dest);puts("");

    if (ip->IHL > 5) {
        printf("SSO: %i\n", ip->shim_size_opt);
        printf("OPR: %i\n", ip->original_protocol);
    }
}

