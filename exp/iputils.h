
#ifndef _IP_UTILS_H_
#define _IP_UTILS_H_

#include <stdint.h>

struct ip_addr {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
} __attribute__ ((aligned (1)));

struct _header_ip {
    uint8_t  IHL : 4;
    uint8_t  version : 4;
    uint8_t  serv_type;
    uint16_t total_length;
    uint16_t identification;
    uint8_t  flags : 4;
    uint16_t frag_offset : 12;
    uint8_t  ttl;
    uint8_t  protocol_id;
    uint16_t checksum;
    struct ip_addr source;
    struct ip_addr dest;
    uint32_t shim_size_opt;
} __attribute__ ((aligned (4)));

struct _tcp {
    uint16_t source_port;
    uint16_t dest_port;
    uint32_t sequence;
    uint32_t ack;
    uint8_t  crap : 4;
    uint8_t  offset : 4;
    uint8_t  shit : 8;
    uint16_t window_size;
    uint16_t checksum;
    uint16_t urgent_shit;
};


struct _shim_stack {
    struct ip_addr shim_ip;
    uint32_t hash;
    uint32_t hash_extra;
} __attribute__ ((aligned (4)));

struct _tcp_payload {
    unsigned char *data;
    uint32_t size;
};

int ip_cmp(struct ip_addr *a, struct ip_addr *b);
void clean_packet(struct _header_ip *h);
struct _tcp_payload data_in(unsigned char *raw);
unsigned char *insert_shim(unsigned char *orig, struct ip_addr addr, uint64_t rando);
void recompute_checksum(unsigned char *data);
unsigned char *strip_shim(unsigned char *data, struct _shim_stack **location, int *sl);

#endif
