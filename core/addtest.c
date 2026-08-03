#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void pfe(const char*n,const fe*a){printf("%s=0x",n);for(int i=3;i>=0;i--)printf("%016llx",(unsigned long long)a->v[i]);printf("\n");}
int main(void){
    point g; memcpy(g.x.v,GX,32); memcpy(g.y.v,GY,32); fe_zero(&g.z); g.z.v[0]=1;
    point g2; pt_double(&g2,&g);
    point g3; pt_add(&g3,&g2,&g);
    uint8_t pub[33];
    pt_serialize_compressed(&g3,pub);
    printf("3G="); for(int i=0;i<33;i++)printf("%02x",pub[i]); printf("\n");
    /* python: 3G compressed = 02f9308a019258c310... */
    printf("want 02f9308a019258c310cee9d31dd6c1047a0bf356b2ae8a60d7e1cb25f2b0d5\n");
    /* debug intermediate: print z1z1 for this add */
    fe z1z1; fe_sqr(&z1z1,&g2.z); pfe("z1z1",&z1z1);
    pfe("g2.z",&g2.z);
    return 0;
}
