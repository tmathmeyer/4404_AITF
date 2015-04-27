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
    clean_packet(ip);
    uint8_t ip_header_size = ip->IHL * 4;
    unsigned char *new_pkt;
    int body_size = ip->total_length - ip_header_size;

    if (ip_header_size == 24) { // has an options field!
        ip->shim_size_opt++; // make the options size bigger
        new_pkt = calloc(ip->total_length + sizeof(struct _shim_stack), 1);
        *size = ip->total_length + sizeof(struct _shim_stack);
        ip->total_length += sizeof(struct _shim_stack);
        ip->protocol = AITF;
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // copy the pack in
    } else {
        uint16_t original_protocol = ip->protocol;
        ip->IHL = 6; // make the packet bigger
        *size = ip->total_length+sizeof(struct _shim_stack)+OPTIONS_LAYER_SIZE;
        new_pkt = calloc(*size, 1);
        ip->total_length = *size;
        ip->protocol = AITF;
        memcpy(new_pkt, ip, sizeof(struct _header_ip)); // write packet

        struct _header_ip *ipn = (struct _header_ip *)new_pkt;
        ipn->shim_size_opt = 1;
        ipn->original_protocol = original_protocol;

    }

    unsigned char *address_area  = new_pkt + sizeof(struct _header_ip);
    unsigned char *random_area   = address_area + IP_ADDR_SIZE;
    unsigned char *old_data_area = random_area + RANDOM_DATA_SIZE;

    // write the shim layer
    memcpy(address_area, &addr, IP_ADDR_SIZE);
    memcpy(random_area,  &rando, RANDOM_DATA_SIZE);

    // insert the rest of the data
    memcpy(old_data_area, orig+ip_header_size, body_size);

    fix_packet((struct _header_ip *)new_pkt);
    recompute_checksum(new_pkt);
    return new_pkt;
}


uchar *strip_shim(uchar *data, struct _shim_stack **location, uint8_t *sl, uint8_t max) {
    struct _header_ip *iph = (struct _header_ip *)data;
    clean_packet(iph);
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

        fix_packet((struct _header_ip *)new_pkt);
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
    uint16_t header_size = ip_header->IHL * 2;
    uint16_t *header_shorts = (uint16_t *)data;
    uint32_t sum = 0;
    size_t counter = 0;

    for(; counter < header_size; counter++) {
        sum += header_shorts[counter];
    }

    while(sum > 0xffff) {
        uint32_t carry = sum >> 16;
        sum &= 0xffff;
        sum += carry;
    }
    uint16_t checksum = sum;

    ip_header->checksum = ~checksum;
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

