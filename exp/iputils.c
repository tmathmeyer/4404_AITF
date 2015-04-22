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



uchar *insert_shim(uchar *orig, struct ip_addr addr, uint64_t rando, uint32_t *size) {
    struct _header_ip *ip = (struct _header_ip *)orig;
    uint8_t ip_header_size = ip->IHL * 4;
    unsigned char *new_pkt;

    if (ip_header_size == 24) { // has an options field!
        ip->shim_size_opt++; // make the options size bigger
        new_pkt = calloc(ip->total_length + sizeof(struct _shim_stack), 1);
        *size = ip->total_length + sizeof(struct _shim_stack);
        ip->total_length += sizeof(struct _shim_stack);
        ip->protocol = AITF;
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // copy the pack in
    } else {
        ip->original_protocol = ip->protocol;
        ip->IHL = 6; // make the packet bigger
        ip->shim_size_opt = 1; // make the shim size 1
        *size = ip->total_length+sizeof(struct _shim_stack)+OPTIONS_LAYER_SIZE;
        new_pkt = calloc(*size, 1);
        ip->total_length = *size;
        ip->protocol = AITF;
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // write packet
    }

    size_t hash_offset = sizeof(struct _header_ip)+4;
    // write the shim layer
    memcpy(new_pkt+sizeof(struct _header_ip), &addr, 4);
    memcpy(new_pkt+hash_offset, &rando, sizeof(uint64_t));


    // insert the rest of the data
    memcpy(new_pkt+sizeof(struct _header_ip)+sizeof(struct _shim_stack),
            orig+ip_header_size, ip->total_length - ip_header_size);

    recompute_checksum(new_pkt);
    return new_pkt;
}


uchar *strip_shim(uchar *data, struct _shim_stack **location, uint8_t *sl, uint8_t max) {
    struct _header_ip *iph = (struct _header_ip *)data;
    if (iph->IHL == PACKET_WITH_OPTIONS) {

        // write the shim size back to the caller
        *sl = iph->shim_size_opt;

        // if the caller wants fewer packets, do this for them
        if (max && *sl > max) {
            *sl = max;
        } else {
            // otherwise, also remove the options and store old protocol
            iph->total_length -= OPTIONS_LAYER_SIZE;
            iph->IHL = PACKET_SANS_OPTIONS;
        }

        // store the size in bytes of the shim
        int shim_size = (*sl) * sizeof(struct _shim_stack);
        // allocate space for shims
        *location = malloc(shim_size);
        // save shime to buffer
        memcpy(*location, data+sizeof(struct _header_ip), shim_size);


        // start piecing together the old packet
        iph->total_length -= shim_size;
        
        // allocate space for the new packet
        unsigned char *new_pkt = malloc(iph->total_length);

        // copy header back to new packet
        int offsetval = iph->IHL * 4;
        memcpy(new_pkt, iph, offsetval);

        //copy payload in
        memcpy(new_pkt+offsetval // write memory to here
               ,data+sizeof(struct _header_ip)+shim_size // write memory from here
               ,iph->total_length-offsetval); // write this much memory
        
        // if the packet is now void of shim shit
        if (iph->IHL == PACKET_SANS_OPTIONS) {
            ((struct _header_ip *)new_pkt) -> protocol = iph->original_protocol;
        }

        recompute_checksum(new_pkt);
        return new_pkt;
    } else { // there was no shim layer!
        *location = NULL;
        *sl = 0;
        return data;
    }
}

void recompute_checksum(unsigned char *data) {
    struct _header_ip *ip_header = (struct _header_ip *)data;
    ip_header->checksum = 0;
    uint32_t checksum_temp = 0xffff;
    uint16_t *checkarr = (uint16_t *)data;
    int indx=0, ctr=0;
    while(ctr++ < (ip_header->IHL)*2) {
        checksum_temp += ntohs(checkarr[indx++]);
        if (checksum_temp>0xffff) {
            checksum_temp-=0xffff;
        }
    }
    checkarr = (uint16_t *)(&checksum_temp);
    ip_header->checksum = htons(checkarr[0] + checkarr[1]);
}

