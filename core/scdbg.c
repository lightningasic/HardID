#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void pbe(const char*n,const uint8_t*a){printf("%s=",n);for(int i=0;i<32;i++)printf("%02x",a[i]);printf("\n");}
int main(void){
    uint8_t a[32]={0},b[32]={0},r[32];
    a[31]=3; b[31]=5;
    os_secp256k1_scalar_mul(r,a,b); pbe("3*5",r);
    uint8_t nm1[32]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                     0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x40};
    os_secp256k1_scalar_mul(r,nm1,nm1); pbe("(n-1)^2",r);
    uint8_t inv[32];
    os_secp256k1_scalar_inv(inv,a);
    os_secp256k1_scalar_mul(r,inv,a); pbe("inv(3)*3",r);
    return 0;
}
