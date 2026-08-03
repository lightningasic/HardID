#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/secp256k1.h"
#include "../core/secp256k1.c"
int main(void){
    uint8_t pub[33];
    /* privkey = 0 rejected */
    uint8_t zero[32]={0};
    if(os_secp256k1_pubkey(zero,pub)==0){printf("FAIL priv=0 accepted\n");return 1;}
    printf("PASS priv=0 rejected\n");
    /* privkey = n rejected */
    uint8_t n[32]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
                   0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41};
    if(os_secp256k1_pubkey(n,pub)==0){printf("FAIL priv=n accepted\n");return 1;}
    printf("PASS priv=n rejected\n");
    /* privkey = n+1 rejected */
    n[31]=0x42;
    if(os_secp256k1_pubkey(n,pub)==0){printf("FAIL priv=n+1 accepted\n");return 1;}
    printf("PASS priv=n+1 rejected\n");
    /* privkey = n-1 accepted (valid) */
    n[31]=0x40;
    if(os_secp256k1_pubkey(n,pub)!=0){printf("FAIL priv=n-1 rejected\n");return 1;}
    printf("PASS priv=n-1 accepted\n");
    /* parse invalid pubkey: wrong prefix */
    uint8_t buf[OS_SECP256K1_POINT_SIZE];
    uint8_t badp[33]; badp[0]=0x04; memset(badp+1,1,32);
    if(os_secp256k1_parse_pubkey(badp,buf)==0){printf("FAIL bad prefix accepted\n");return 1;}
    printf("PASS bad prefix rejected\n");
    /* parse pubkey with x >= p rejected */
    uint8_t bigx[33]; bigx[0]=0x02; memset(bigx+1,0xff,32);
    if(os_secp256k1_parse_pubkey(bigx,buf)==0){printf("FAIL x>=p accepted\n");return 1;}
    printf("PASS x>=p rejected\n");
    printf("\nALL ROUND-21 secp256k1 TESTS PASSED\n");
    return 0;
}
