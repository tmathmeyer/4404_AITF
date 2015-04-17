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
	h->identification = ntohs(h->identification);
}

struct _tcp_payload data_in(unsigned char *raw) {
    struct _header_ip *h = (struct _header_ip *)raw;
    uint8_t ip_header_size = h->IHL * 4;
    uint32_t ip_payload_size = h->total_length - ip_header_size;
    raw += ip_header_size; // remove IP Header
    struct _tcp *tcp = (struct _tcp *)raw; // should check if tcp or udp later

    uint8_t tcp_header_size = tcp->offset * 4;
    struct _tcp_payload payload;
    payload.data = raw+tcp_header_size;
    payload.size = ip_payload_size - tcp_header_size;
    return payload;
}

unsigned char *insert_shim(unsigned char *orig, struct ip_addr addr, uint64_t rando) {
    struct _shim_stack pushme;
    pushme.shim_ip = addr;
    *(uint64_t *)(&(pushme.hash1)) = rando;

    struct _header_ip *ip = (struct _header_ip *)orig;
    uint8_t ip_header_size = ip->IHL * 4;
    unsigned char *new_pkt;

    if (ip_header_size == 24) { // has an options field!
        ip->shim_size_opt++; // make the options size bigger
        new_pkt = calloc(ip->total_length + sizeof(struct _shim_stack), 1); // make packet
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // copy the pack in
    } else {
        ip->IHL ++; // make the packet bigger
        ip->shim_size_opt = 1; // make the shim size 1
        int size = ip->total_length + sizeof(struct _shim_stack) + 4;
        new_pkt = calloc(size, 1);
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // write packet
    }

    // write the shim layer
    memcpy(new_pkt+sizeof(struct _header_ip), &pushme, sizeof(struct _shim_stack));
    
    // insert the rest of the data
    memcpy(new_pkt+sizeof(struct _header_ip)+sizeof(struct _shim_stack),
                    orig+ip_header_size, ip->total_length - ip_header_size);
    
    recompute_checksum(new_pkt);
    return new_pkt;
}

unsigned char *strip_shim(unsigned char *data, struct _shim_stack **location, int *sl) {
    struct _header_ip *iph = (struct _header_ip *)data;
    if (iph->IHL == 6) {
        // save the shim stack
        *sl = iph->shim_size_opt;
        int shim_size = iph->shim_size_opt * sizeof(struct _shim_stack);
        *location = malloc(shim_size);
        memcpy(*location, data+sizeof(struct _header_ip), shim_size);

        // start piecing together the old packet
        iph->total_length -= shim_size;
        iph->IHL = 5;
        unsigned char *new_pkt = malloc(iph->total_length);
        recompute_checksum(new_pkt);
        
        // copy header back to new packet
        memcpy(new_pkt, iph, 20);

        //copy payload in
        memcpy(new_pkt, data+12+shim_size, iph->total_length-4+shim_size);
        
        return new_pkt;
    } else { // there was no shim layer!
        *location = NULL;
        return data;
    }
}



void recompute_checksum(unsigned char *data) {
    struct _header_ip *ip_header = (struct _header_ip *)data;
    ip_header->checksum = 0;
    uint32_t checksum_temp = 0;
    uint16_t *checkarr = (uint16_t *)data;
    int indx=0, ctr=0;
    while(ctr < ip_header->IHL) {
        checksum_temp += (checkarr[indx] + checkarr[indx+1]);
        ctr++;
        indx += 2;
    }
    checkarr = (uint16_t *)(&checksum_temp);
    ip_header->checksum = checkarr[0] + checkarr[1];
}

