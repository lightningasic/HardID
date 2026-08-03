#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void pfe(const char *n, const fe *a){ printf("%s=0x",n); for(int i=3;i>=0;i--)printf("%016llx",(unsigned long long)a->v[i]); printf("\n"); }
int main(void){
    point g;
    memcpy(g.x.v, GX, 32); memcpy(g.y.v, GY, 32);
    fe_zero(&g.z); g.z.v[0]=1;
    point r;
    pt_double(&r, &g);
    uint8_t pub[33];
    pt_serialize_compressed(&r, pub);
    printf("2G = ");
    for(int i=0;i<33;i++)printf("%02x",pub[i]);
    printf("\nwant 02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5\n");
    /* also dump affine x/y */
    fe zinv,z2,z3,ax,ay;
    fe_inv(&zinv,&r.z); fe_sqr(&z2,&zinv); fe_mul(&z3,&z2,&zinv);
    fe_mul(&ax,&r.x,&z2); fe_mul(&ay,&r.y,&z3);
    pfe("ax",&ax); pfe("ay",&ay);
    return 0;
}
