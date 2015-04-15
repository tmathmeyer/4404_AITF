
#ifndef _IP_UTILS_H_
#define _IP_UTILS_H_

#include <stdint.h>

struct ip_addr {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    uint8_t d;
};

struct _header_ip {
    uint8_t  version : 4;
    uint8_t  IHL : 4;
    uint8_t  serv_type;
    uint16_t total_length;
    uint16_t identification;
    uint8_t  flags : 4;
    uint16_t frag_offset : 12;
    uint8_t  ttl;
    uint8_t  protocol_id;
    uint16_t checksum;
    struct ip_addr  source;
    struct ip_addr  dest;
};

int ip_cmp(struct ip_addr *a, struct ip_addr *b);

#endif