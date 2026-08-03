#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/bip39.h"
#include "../core/sha512.h"
#include "../core/sha512.c"
#include "../core/hkdf.c"
#include "../core/bip39.c"
int main(void){
    uint8_t rec[32];
    /* empty string -> 0 words, rejected */
    if(os_bip39_mnemonic_to_entropy("", rec, sizeof rec)!=0){printf("FAIL empty accepted\n");return 1;}
    printf("PASS empty rejected\n");
    /* only spaces -> 0 words, rejected */
    if(os_bip39_mnemonic_to_entropy("     ", rec, sizeof rec)!=0){printf("FAIL spaces accepted\n");return 1;}
    printf("PASS all-spaces rejected\n");
    /* single valid word -> wrong count, rejected */
    if(os_bip39_mnemonic_to_entropy("abandon", rec, sizeof rec)!=0){printf("FAIL single word accepted\n");return 1;}
    printf("PASS single word rejected\n");
    /* uppercase variant -> not in list, rejected (BIP39 is lowercase) */
    if(os_bip39_mnemonic_to_entropy("ABANDON abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", rec, sizeof rec)!=0){printf("FAIL uppercase accepted\n");return 1;}
    printf("PASS uppercase rejected\n");
    /* leading/trailing multiple spaces still fine */
    if(os_bip39_mnemonic_to_entropy("  abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about  ", rec, sizeof rec)!=16){printf("FAIL padded valid rejected\n");return 1;}
    printf("PASS padded valid accepted\n");
    /* 11 words -> rejected */
    if(os_bip39_mnemonic_to_entropy("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon", rec, sizeof rec)!=0){printf("FAIL 11 words accepted\n");return 1;}
    printf("PASS 11 words rejected\n");
    /* entropy_to_mnemonic: bad length rejected */
    char m[256]; uint8_t bad[17]={0};
    if(os_bip39_entropy_to_mnemonic(bad,17,m,sizeof m)!=0){printf("FAIL bad entropy len accepted\n");return 1;}
    printf("PASS bad entropy length rejected\n");
    printf("\nALL ROUND-18 TESTS PASSED\n");
    return 0;
}
