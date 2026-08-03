#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/bip32.h"
#include "../core/sha512.c"
#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/secp256k1.c"
#include "../core/bip32.c"
int main(void){
    uint8_t seed[16]={0};
    os_hdnode m;
    os_bip32_from_seed(seed,16,&m);
    os_hdnode n;
    /* valid path still works */
    n=m; if(os_bip32_derive_path(&n,"m/44'/0'/0'/0/0")!=0){printf("FAIL valid path\n");return 1;}
    printf("PASS valid path m/44'/0'/0'/0/0\n");
    /* index 2^31 must be rejected (would collide with hardened flag) */
    n=m; if(os_bip32_derive_path(&n,"m/2147483648")==0){printf("FAIL accepted 2^31\n");return 1;}
    printf("PASS rejects index 2^31\n");
    /* huge overflow index rejected */
    n=m; if(os_bip32_derive_path(&n,"m/99999999999")==0){printf("FAIL accepted huge index\n");return 1;}
    printf("PASS rejects overflow index\n");
    /* max valid non-hardened index 2^31-1 accepted */
    n=m; if(os_bip32_derive_path(&n,"m/2147483647")!=0){printf("FAIL rejected max valid index\n");return 1;}
    printf("PASS accepts max valid index 2^31-1\n");
    printf("\nALL ROUND-11 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
