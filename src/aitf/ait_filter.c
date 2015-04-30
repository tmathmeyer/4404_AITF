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
#include <fcntl.h>
#include "iputils.h"
#include "dlist.h"

uint64_t salt;
int debug_level = 0;
dlist *ipmap;
dlist *filter;

void init_salt() {
    int file = open("/dev/urandom", O_RDONLY);
    if (file < 0) {
        salt = 42;
        puts("fuck, cannot read /dev/urandom");
    } else {
        read(file, &salt, sizeof(uint64_t));
    }
}

void light(char *fail) {
    if (debug_level > 0) {
        printf("%s", fail);
    }
}

void alot(char *fail) {
    if (debug_level > 1) {
        printf("%s", fail);
    }
}

void toofuckingmuch(char *fail) {
    if (debug_level > 2) {
        printf("%s", fail);
    }
}


void print_block_time_ips(struct ip_pair *pair) {
    if (debug_level > 1) {
        printf("Blocked traffic between:\n  ");
        print_ip(pair->A);
        printf("\n  ");
        print_ip(pair->B);
    }
    printf("\nat time: %lu\n", aitf_milis());
}


void create_filter_rule(struct ip_addr A, struct ip_addr B) {
    struct ip_pair *pair = malloc(sizeof(struct ip_pair));
    memcpy(pair, &A, sizeof(struct ip_addr));
    memcpy(&(pair->B), &B, sizeof(struct ip_addr));
    dlist_add(filter, pair);
    print_block_time_ips(pair);
}

#define I4 struct ip_addr
bool ip_mixmatch(I4 X, I4 x, I4 Y, I4 y) {
    int m = ip_cmp(&X, &x) && ip_cmp(&Y, &y);
    int n = ip_cmp(&Y, &x) && ip_cmp(&X, &y);
    return m||n;
}

bool matches_filter_rule(struct ip_addr A, struct ip_addr B) {
    struct ip_pair *pair;
    each(filter, pair) {
        if (ip_mixmatch(pair->A, A, pair->B, B)) {
            return true;
        }
    }
    return false;
}



void insert_shim_for_ip(struct ip_addr addr, struct _shim_stack *shims, size_t shimc) {
    struct ip_map *map;
    struct _shim_stack *freeme;
    each(ipmap, map) {
        if (ip_cmp(&addr, &(map->address))) {
            freeme = map->shims;
            map->shims = shims;
            map->shim_count = shimc;
            free(freeme);
            return;
        }
    }

    map = malloc(sizeof(struct ip_map));
    memcpy(map, &addr, sizeof(struct ip_addr));
    map->shims = shims;
    map->shim_count = shimc;

    dlist_add(ipmap, map);
}

struct _shim_stack *get_shim_for_ip(struct ip_addr addr, size_t *size) {
    struct ip_map *map = NULL;
    each(ipmap, map) {
        if (map!=NULL && ip_cmp(&addr, &(map->address))) {
            *size = map->shim_count;
            return map->shims;
        }
    }
    *size = 0;
    return NULL;
}

void print_shims(struct _shim_stack *shims, size_t shimc) {
    while(shimc) {
        shimc--;
        if (debug_level > 1) {
            printf("  [%zd] -> %i %i :: ", shimc, shims[shimc].hash, shims[shimc].hash_extra);
            print_ip(shims[shimc].shim_ip);
            printf("\n");
        }
    }
}


bool internal_ip(struct ip_addr address) {
    if (address.a != 10) return false;
    if (address.b != 4) return false;
    if (address.c != 31) return false;
    return true;
}

bool internal_packet(struct _header_ip *header) {
    return internal_ip(header->source) && internal_ip(header->dest);
}


void calcMD5(uint64_t *hash, uint64_t *salty, uint64_t *ip) {
    unsigned char input[16];
    unsigned char temp_result[16];
    *((uint64_t *)input) = *salty;
    *((uint64_t *)(input+8)) = *ip;
    MD5(input, 16, temp_result);
    *hash = *((uint64_t *) temp_result) ^ *((uint64_t *)(temp_result+8));
}

//Calculates the hash using the MD% hashing function
uint64_t hash(struct _header_ip *header) {
    struct ip_addr IPs[2];
    IPs[0] = header->source; // victim
    IPs[1] = header->dest;   // attacker
    
    uint64_t result;
    calcMD5(&result, &salt, (uint64_t *)(IPs));
    return result;
}

bool validate(struct _header_ip *header, struct _shim_stack *shims) {
    struct ip_addr IPs[2];
    IPs[0] = header->dest;   // attacker
    IPs[1] = header->source; // victim
    
    uint64_t supplied_hash = *((uint64_t *)&(shims->hash));
    uint64_t recalc_hash;
    calcMD5(&recalc_hash, &salt, (uint64_t *)(IPs));

    return recalc_hash == supplied_hash;
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
        toofuckingmuch("attempted to read a packet, but failed\n");
        return false;
    } else {
        toofuckingmuch("recieved a packet\n");
    }


    ip = (struct _header_ip *)original;

    if (matches_filter_rule(ip->source, ip->dest)) {
        toofuckingmuch("blocked packet!");
        return -1;
    }

    if (!internal_packet(ip)) {
        toofuckingmuch("the packet was not internal to the system\n");
        return 0;
    } else {
        toofuckingmuch("parsing the packet:\n");
#ifdef CORE
        toofuckingmuch("  --> CORE ROUTER\n");
#endif
#ifdef GATE
        toofuckingmuch("  --> GATEWAY ROUTER\n");
#endif
    }





#ifdef CORE
    struct ip_addr ATK2 = {8, 8, 8, 8};
    ATK = ATK2;
    // if the protocol is PPM, validate the packet
    // otherwise, pass it along with shim
    if (ip->protocol == PPM) {
        alot("core router recieved a PPM\n");
        // remove top shim (should be for us) and validate it
        struct _shim_stack *shims;
        uint8_t shimc;
        *wb = strip_shim(original, &shims, &shimc, ALL_SHIMS, size);

        // if this is the last chain in the line
        if (ip->shim_size_opt == 0) {
            // install filter
            //filter_throughput(ip);
            alot("filtering the jerk who is spamming me\n");
            return -1;
        }

        // there are no shims, or the shim is shit
        if (shimc == 0 || !validate(ip, shims)) {
            alot("bad shim layer, or non-existant layer\n");
            return false;
        }

        // keep going!
        return true;
    } else if(ip->protocol == PPM) {
        light("recieved a PPM Packet!!!!!");
        struct _shim_stack *shims;
        uint8_t shimc;
        
        light("+=PPM PACKET========\n");
        *wb = strip_shim(original, &shims, &shimc, 1, size);
        alot("shims: \n");
        printf("%i\n", shimc);
        print_shims(shims, shimc);
        if (shimc == 1) {
            if (validate(ip, shims)) {
                create_filter_rule(ip->dest, ip->source);
            } else {
                free(*wb);
                return -1;
            }
        } else {
            // what the shit just happened?
        }
        
        light("+=PPM PAKCET========\n\n\n");
        
        return *wb != NULL;
        //if we get a PPM packet from an attacker, we need to filter!!
    }
#endif // CORE ROUTER
#ifdef GATE
    if (ip->protocol == FILTER) {
        size_t shimc;
        struct _shim_stack *shims = get_shim_for_ip(ip->dest, &shimc);
        
        alot("+=FILTER REQUEST=====\n");
        if (debug_level > 0) {
            print_ip(ip->source);
            printf(" is asking for protection from ");
            print_ip(ip->dest);
            
            if (shimc > 0) {
                print_shims(shims, shimc);
            } else {
                puts("\nthere were no shims! :O nothing can be done!");
            }
        }
        alot("+FILTER REQUEST=====\n\n\n");

        if (shimc > 0) {
            *wb = create_ppm(ip, shims, shimc, size);
            return *wb != NULL;
        } else {
            return -1;
        }

    } else if(ip->protocol == PPM) {
        puts("recieved a PPM Packet!!!!!");
        struct _shim_stack *shims;
        uint8_t shimc;
        
        light("+=PPM PACKET========\n");
        *wb = strip_shim(original, &shims, &shimc, ALL_SHIMS, size);
        alot("shims: \n");
        printf("%i\n", shimc);
        print_shims(shims, shimc);
        if (shimc == 1) {
            if (validate(ip, shims)) {
                create_filter_rule(ip->dest, ip->source);
            } else {
                puts("fuck");
            }
        }
        
        free(*wb);
        light("+=PPM PAKCET========\n\n\n");
        
        return -1;
        //if we get a PPM packet from an attacker, we need to filter!!
    } else if (ip->protocol == AITF) {
        // if we get an AITF packet as a gateway router, strip it
        struct _shim_stack *shims;
        uint8_t shimc;

        light("+=AITF PACKET========\n");
        *wb = strip_shim(original, &shims, &shimc, ALL_SHIMS, size);
        alot("shims:\n");
        print_shims(shims, shimc);
        insert_shim_for_ip(ip->source, shims, shimc);
        light("+=AITF PACKET========\n\n\n");

        return *wb != NULL;
    }
#endif // GATEWAY_ROUTER
    //insert shim layer, pass along the packet
    light("+=NORMAL PACKET=============\n");
    if (debug_level > 1) {
        pretty_print_packet((struct _header_ip *)original);
    }
    *wb = insert_shim(original, ATK, hash(ip), size);
    light("+=NORMAL PACKET=============\n\n");
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
    
    int packet_val = monitor_packet(nfa, &new_pkt, &size);

    if(packet_val == 1) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, size, new_pkt);
    } else if (packet_val == 0) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    } else {
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}









void usage() {
    puts("netfilter [-v level]");
    puts("    -v level");
    puts("          level = [light, rambling, annoying, obnoxious]");
}


int main(int argc, char **argv) {
    ipmap = dlist_new();
    filter = dlist_new();
    init_salt();
    
    int ctr = 0;
    while(++ctr < argc) {
        if (!(strncmp(argv[ctr], "-v", 2)&&strncmp(argv[ctr], "--verbose", 8))){
            if (ctr >= argc-1) {
                usage();
                exit(0);
            } else {
                ctr++;
                if (!strncmp(argv[ctr], "light", 5)) {
                    puts("light debugging");
                    debug_level = 1;
                } else if (!strncmp(argv[ctr], "rambling", 8)) {
                    puts("rambling debugging");
                    debug_level = 2;
                } else if (!strncmp(argv[ctr], "annoying", 8)) {
                    puts("annoying debugging");
                    debug_level = 3;
                } else if (!strncmp(argv[ctr], "obnoxious", 9)) {
                    puts("too fucking much debugging");
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

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    nfq_destroy_queue(qh);

    nfq_close(h);

    exit(0);
}
