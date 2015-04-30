
#ifndef _IP_UTILS_H_
#define _IP_UTILS_H_

#include <stdint.h>
#define PPM 254
#define AITF 253
#define FILTER 252
#define ALL_SHIMS 0
#define PACKET_WITH_OPTIONS 6
#define PACKET_SANS_OPTIONS 5
#define OPTIONS_LAYER_SIZE 4
#define IP_ADDR_SIZE 4
#define RANDOM_DATA_SIZE 8
#define uchar unsigned char

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
    uint8_t  protocol;
    uint16_t checksum;
    struct ip_addr source;
    struct ip_addr dest;
    uint8_t shim_size_opt;
    uint8_t original_protocol;
    uint16_t buffer;
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

struct ip_pair {
    struct ip_addr A;
    struct ip_addr B;
};

struct ip_map {
    struct ip_addr address;
    struct _shim_stack *shims;
    size_t shim_count;
};

int ip_cmp(struct ip_addr *a, struct ip_addr *b);
void clean_packet(struct _header_ip *h);
struct _tcp_payload data_in(uchar *raw);
uchar *insert_shim(uchar *orig, struct ip_addr addr, uint64_t rando, uint32_t *size);
void recompute_checksum(uchar *data);
uchar *strip_shim(uchar *data, struct _shim_stack **location, uint8_t *sl, uint8_t max, uint32_t *size);
void fancy_print_packet(struct _header_ip *ip);
void print_ip(struct ip_addr ip);
void fix_packet(struct _header_ip *h);
void pretty_print_packet(struct _header_ip *ip);
void print_bytes(struct _header_ip *header);
uchar *create_ppm(struct _header_ip *orig, struct _shim_stack *shims, size_t shimc, uint32_t *size);
uint64_t aitf_milis();
#endif
