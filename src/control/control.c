#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "iputils.h"

 
int main (void) {
    int one = 1;
    struct sockaddr_in sin;
    int s = socket (PF_INET, SOCK_RAW, IPPROTO_TCP);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("10.4.31.5");

    const int *val = &one;
    struct sockaddr *sinp = (struct sockaddr *)(&sin);

    

    if(s == -1) {
        perror("Failed to create socket... are you root?");
        exit(1);
    }
     
    if (setsockopt (s, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(0);
    }

    struct ip_addr source;
    struct ip_addr dest;

    source.a = 10;
    source.b = 4;
    source.c = 31;
    source.d = 1;
    scanf("%i.%i.%i.%i", (int *)&(dest.a), (int *)&(dest.b), (int *)&(dest.c), (int *)&(dest.d));


    //Datagram to represent the packet
    unsigned char datagram[sizeof(struct _header_ip)];
    memset (datagram, 0, sizeof(struct _header_ip));

    struct _header_ip *ip = (struct _header_ip *)datagram;
    ip->IHL = 6;
    ip->version = 4;
    ip->serv_type = 0;
    ip->total_length = 24;
    ip->identification = 0xfbfb;
    ip->flags = 0;
    ip->frag_offset = 0;
    ip->ttl = 189;
    ip->protocol = FILTER;
    ip->checksum = 0;
    ip->source = source;  // get my IP
    ip->dest = dest;
    ip->shim_size_opt = 0;
    ip->original_protocol = FILTER;
    ip->buffer = 0;
    fix_packet(ip);
    recompute_checksum(datagram);


    if (sendto (s, datagram, ntohs(ip->total_length), 0, sinp, sizeof(sin)) < 0) {
        perror("oh shit, couldn't communicate with gateway");
    }
     
    return 0;
}
