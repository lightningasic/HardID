#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "secp256k1.h"
#include "secp256k1.c"
static void show(const char*n, const uint8_t*k){
    uint8_t pub[33];
    if(os_secp256k1_pubkey(k,pub)!=0){printf("%s FAIL\n",n);return;}
    printf("%s: ",n);
    for(int i=0;i<9;i++)printf("%02x",pub[i]);
    printf("...\n");
}
int main(void){
    uint8_t k[32]={0};
    k[31]=3; show("3",k);
    k[31]=4; show("4",k);
    k[31]=7; show("7",k);
    k[31]=0x10; show("0x10",k);
    k[31]=0xff; show("0xff",k);
    k[31]=0; k[30]=1; show("0x100",k);
    return 0;
}
