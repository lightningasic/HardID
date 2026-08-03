#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/base58.h"
#include "../core/hkdf.c"
#include "../core/base58.c"
int main(void){
    char out[200];
    /* len==0 rejected */
    if(os_base58_encode_check((const uint8_t*)"",0,out,sizeof out)!=0){printf("FAIL len0 accepted\n");return 1;}
    printf("PASS base58 len0 rejected\n");
    /* len>96 rejected */
    uint8_t big[100]; memset(big,1,100);
    if(os_base58_encode_check(big,100,out,sizeof out)!=0){printf("FAIL len>96 accepted\n");return 1;}
    printf("PASS base58 len>96 rejected\n");
    /* outmax too small rejected */
    uint8_t d[21]={0};
    if(os_base58_encode_check(d,21,out,5)!=0){printf("FAIL small outmax accepted\n");return 1;}
    printf("PASS base58 small outmax rejected\n");
    /* all-zero payload -> '1' leading chars */
    size_t n = os_base58_encode_check(d,21,out,sizeof out);
    if(n==0 || out[0]!='1'){printf("FAIL leading zero\n");return 1;}
    printf("PASS base58 leading-zero handling\n");
    printf("\nALL ROUND-19 base58 TESTS PASSED\n");
    return 0;
}
