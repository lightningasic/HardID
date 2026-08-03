#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/clearsign.h"
#include "../core/keccak.c"
#include "../core/clearsign.c"

/* 构造各种畸形 RLP 验证解析器不崩溃且正确拒绝 */
static int try_parse(const uint8_t *d, size_t n){
    os_tx_intent it;
    return os_clearsign_parse_evm(d, n, &it);
}
int main(void){
    /* long-form length field claiming huge length (ll=4, len=0xFFFFFFFF) */
    uint8_t huge[] = {0xbb, 0xff,0xff,0xff,0xff};
    if(try_parse(huge, sizeof huge)==0){printf("FAIL huge len accepted\n");return 1;}
    printf("PASS huge length rejected\n");
    /* long-form with ll=5 (>4) rejected */
    uint8_t ll5[] = {0xbc, 1,2,3,4,5};
    if(try_parse(ll5, sizeof ll5)==0){printf("FAIL ll=5 accepted\n");return 1;}
    printf("PASS ll>4 rejected\n");
    /* truncated list header */
    uint8_t trunc[] = {0xf8, 0x10};
    if(try_parse(trunc, sizeof trunc)==0){printf("FAIL truncated accepted\n");return 1;}
    printf("PASS truncated header rejected\n");
    /* list claiming length beyond buffer */
    uint8_t over[] = {0xf8, 0xff, 0x01,0x02,0x03};
    if(try_parse(over, sizeof over)==0){printf("FAIL over-claim accepted\n");return 1;}
    printf("PASS over-claimed length rejected\n");
    /* empty input */
    if(try_parse((const uint8_t*)"",0)==0){printf("FAIL empty accepted\n");return 1;}
    printf("PASS empty rejected\n");
    /* single byte 0x00 (valid RLP single byte) — should parse as unknown/edge */
    uint8_t single[] = {0x00};
    int r = try_parse(single, sizeof single);
    printf("PASS single byte handled (rc=%d, no crash)\n", r);
    /* nested empty list as top-level */
    uint8_t nested[] = {0xc0};
    if(try_parse(nested, sizeof nested)==0){printf("FAIL empty list accepted as tx\n");return 1;}
    printf("PASS empty list rejected as tx\n");
    printf("\nALL ROUND-20 RLP TESTS PASSED\n");
    return 0;
}
