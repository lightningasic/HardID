#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void pfe(const char*n,const fe*a){printf("%s=0x",n);for(int i=3;i>=0;i--)printf("%016llx",(unsigned long long)a->v[i]);printf("\n");}
int main(void){
    point g; memcpy(g.x.v,GX,32); memcpy(g.y.v,GY,32); fe_zero(&g.z); g.z.v[0]=1;
    point g2; pt_double(&g2,&g);
    point *p=&g2, *q=&g;
    fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t;
    fe_sqr(&z1z1, &p->z); fe_sqr(&z2z2, &q->z);
    fe_mul(&u1, &p->x, &z2z2); fe_mul(&u2, &q->x, &z1z1);
    fe_mul(&t, &q->z, &z2z2); fe_mul(&s1, &p->y, &t);
    fe_mul(&t, &p->z, &z1z1); fe_mul(&s2, &q->y, &t);
    fe_sub(&h, &u2, &u1);
    fe_add(&i, &h, &h); fe_sqr(&i, &i);
    fe_mul(&j, &h, &i);
    fe_sub(&t, &s2, &s1);
    fe_add(&rr, &t, &t);
    fe_mul(&v, &u1, &i);
    pfe("i",&i); pfe("j",&j); pfe("rr",&rr); pfe("v",&v);
    return 0;
}
