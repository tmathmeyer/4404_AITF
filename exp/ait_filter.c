#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <openssl/md5.h>
#include "iputils.h"


void blockIP(struct ip_addr *ip) {
    char buff[100] = {0};
    sprintf(buff, "iptables -A INPUT -s %d.%d.%d.%d -j DROP",
            ip->a, ip->b, ip->c, ip->d);
    system(buff);
}

bool debug_flag = 1;

int printable(char c) {
    if (c >= 33 && c <= 126) {
        return 1;
    }

    return 0;
}

void print_tcp(unsigned char *data, uint16_t size) {
    int i = 0;
    while(size) {
        if (printable(*data)) {
            putchar('-');
            putchar(' ');
            putchar(*data);
            putchar('-');
        } else {
            printf("-%x-", *data);
        }

        if ((++i)%16 == 0) {
            printf("\n");
        }

        data ++;
        size --;
    }
}

bool internal_ip(struct ip_addr address) {
    if (address.a != 10) return false;
    if (address.b != 4) return false;
    if (address.c != 31) return false;
    return true;
}

bool internal_packet(struct _header_ip *header) {
    // source and destination must be internal
    return internal_ip(header->source) && internal_ip(header->dest);
}


void calcMD5(uint64_t *hash, uint64_t *salt, uint64_t *ip) {
    unsigned char input[16];
    unsigned char temp_result[16];
    *((uint64_t *)input) = *salt;
    *((uint64_t *)(input+8)) = *ip;
    MD5(input, 16, temp_result);
    *hash = *((uint64_t *) temp_result) ^ *((uint64_t *)(temp_result+8));

    if(debug_flag) {
        printf("Hash: %lu\n", *hash);
    }
}

//Calculates the hash using the MD% hashing function
uint64_t hash(struct _header_ip *header) {
    uint64_t result;
    uint64_t salt = 42;
    calcMD5(&result, &salt, (uint64_t *)(&(header->source)));
    return result;
}

bool validate(struct _header_ip *header, struct _shim_stack *shims) {
    uint64_t currentHash; 
    currentHash = *((uint64_t *)&(shims->hash));
    return currentHash == hash(header);
}


struct ip_addr MSI = {.a=0, .b=0, .c=0, .d=0};
struct ip_addr ATK = {.a=10, .b=4, .c=31, .d=1};
struct ip_addr VIC = {.a=10, .b=4, .c=31, .d=4};

bool is_route(struct ip_addr X, struct ip_addr Y) {
    int x = ip_cmp(&X, &ATK) && ip_cmp(&Y, &VIC);
    int y = ip_cmp(&Y, &ATK) && ip_cmp(&X, &VIC);

    return x||y;
}



/*
 * 1  -> send the new packet in wb
 * 0  -> send the old packet
 * -1 -> send nothing at all
 */
int monitor_packet(struct nfq_data *tb, unsigned char **wb, uint32_t *size) {
    unsigned char *original;
    struct _header_ip *ip;

    if (nfq_get_payload(tb, &original) < 0) {
        // no packet, return false
        *size = 0;
        *wb = NULL;
        return false;
    }

    ip = (struct _header_ip *)original;

    if (!internal_packet(ip)) {
        return 0;
    }



#ifdef CORE_ROUTER
    struct ip_addr ATK2 = {8, 8, 8, 8};
    ATK = ATK2;
    // if the protocol is PPM, validate the packet
    // otherwise, pass it along with shim
    if (ip->protocol == PPM) {
        // remove top shim (should be for us) and validate it
        struct _shim_stack *shims;
        uint8_t shimc;
        *wb = strip_shim(original, &shims, &shimc, ALL_SHIMS, size);

        // there are no shims, or the shim is shit
        if (shimc == 0 || !validate(ip, shims)) {
            return false;
        }

        // if this is the last chain in the line
        if (ip->shim_size_opt == 0) {
            // install filter
            //filter_throughput(ip);
            return -1;
        }

        // keep going!
        return true;
    }
#endif // CORE ROUTER
#ifdef GATEWAY_ROUTER
    if (ip->protocol == FILTER) {
        // negotiate handshake with other
        // do things
    } else if(ip->protocol == PPM) {
        //if we get a PPM packet from an attacker, we need to filter!!
    } else if (ip->protocol == AITF) {
        // if we get an AITF packet as a gateway router, strip it
        struct _shim_stack *shims;
        uint8_t shimc;

        puts("+=AITF PACKET========");
        *wb = strip_shim(original, &shims, &shimc, ALL_SHIMS, size);
        puts("shims:");
        while(shimc) {
            shimc--;
            printf("  [%i] -> %i :: ", shimc, shims[shimc].hash);
            print_ip(shims[shimc].shim_ip);
            printf("\n");
        }
        puts("+=AITF PACKET========\n\n");

        return *wb != NULL;
    }
#endif // GATEWAY_ROUTER
    //insert shim layer, pass along the packet
    puts("+=INSERTED SHIM=============\n");
    pretty_print_packet((struct _header_ip *)original);
    *wb = insert_shim(original, ATK, 42, size);
    puts("+=INSERTED SHIM=============\n\n");
    return *wb != NULL;
}

#define handle struct nfq_q_handle
int cb(handle *qh, struct nfgenmsg *msg, struct nfq_data *nfa, void *data) {
    (void) msg; // specifically disable this
    (void) data;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    int id = ph?ntohl(ph->packet_id):0;

    unsigned char *new_pkt;
    uint32_t size;
    if(monitor_packet(nfa, &new_pkt, &size) == 1) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, size, new_pkt);
    } else {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
}









void usage() {
    puts("netfilter [-v level]");
    puts("    -v level");
    puts("          level = [light, rambling, annoying, obnoxious]");
}


int debug_level = 0;
int main(int argc, char **argv) {

    int ctr = 0;
    while(++ctr < argc) {
        if (!(strncmp(argv[ctr], "-v", 2)&&strncmp(argv[ctr], "--verbose", 8))){
            if (ctr >= argc-1) {
                usage();
                exit(0);
            } else {
                ctr++;
                if (!strncmp(argv[ctr], "light", 5)) {
                    debug_level = 1;
                } else if (!strncmp(argv[ctr], "rambling", 8)) {
                    debug_level = 2;
                } else if (!strncmp(argv[ctr], "annoying", 8)) {
                    debug_level = 3;
                } else if (!strncmp(argv[ctr], "obnoxious", 9)) {
                    debug_level = 4;
                }
            }
        }
    }




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
