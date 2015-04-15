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