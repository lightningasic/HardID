#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void pfe(const char*n,const fe*a){printf("%s=0x",n);for(int i=3;i>=0;i--)printf("%016llx",(unsigned long long)a->v[i]);printf("\n");}
int main(void){
    point g; memcpy(g.x.v,GX,32); memcpy(g.y.v,GY,32); fe_zero(&g.z); g.z.v[0]=1;
    point g2; pt_double(&g2,&g);
    /* now manual pt_add with prints */
    point *p=&g2, *q=&g;
    fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t;
    fe_sqr(&z1z1, &p->z);
    fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2);
    fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&t, &q->z, &z2z2);
    fe_mul(&s1, &p->y, &t);
    fe_mul(&t, &p->z, &z1z1);
    fe_mul(&s2, &q->y, &t);
    fe_sub(&h, &u2, &u1);
    pfe("u1",&u1); pfe("u2",&u2); pfe("s1",&s1); pfe("s2",&s2); pfe("h",&h);
    pfe("g2.x",&g2.x); pfe("g2.y",&g2.y); pfe("g2.z",&g2.z);
    return 0;
}
