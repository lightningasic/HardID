/* Round 13: malicious huge maxFee must not wrap fee_limit to a small value */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/clearsign.h"
#include "../core/keccak.c"
#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/psbt.c"
#include "../core/clearsign.c"
static size_t rlp_hdr(uint8_t *o,int list,size_t l){uint8_t b=list?0xc0:0x80; if(l<56){o[0]=b+l;return 1;} o[0]=b+56;o[1]=l;return 2;}
static size_t rlp_str(uint8_t *o,const uint8_t*d,size_t l){size_t h=rlp_hdr(o,0,l); if(l&&d)memcpy(o+h,d,l); return h+l;}
static size_t rlp_u(uint8_t *o,uint64_t v){uint8_t b[8];int n=0; if(v==0){o[0]=0x80;return 1;} if(v<0x80){o[0]=(uint8_t)v;return 1;} while(v){b[7-n++]=v&0xff;v>>=8;} return rlp_str(o,b+8-n,n);}

static size_t build_legacy(uint8_t *o, uint64_t gasPrice, uint64_t gasLimit, uint64_t value){
    uint8_t to[20]; memset(to,0x11,20);
    uint8_t tmp[256]; size_t t=0;
    t += rlp_u(tmp+t,1);
    t += rlp_u(tmp+t,gasPrice);
    t += rlp_u(tmp+t,gasLimit);
    t += rlp_str(tmp+t,to,20);
    t += rlp_u(tmp+t,value);
    t += rlp_str(tmp+t,NULL,0);
    size_t h=rlp_hdr(o,1,t); memcpy(o+h,tmp,t);
    return h+t;
}

int main(void){
    os_tx_intent it;
    uint8_t tx[512];
    /* normal fee: 20 * 21000 = 420000 */
    size_t n = build_legacy(tx, 20, 21000, 1000);
    os_clearsign_parse_evm(tx, n, &it);
    if (it.fee_limit != 420000) { printf("FAIL normal fee=%llu\n",(unsigned long long)it.fee_limit); return 1; }
    printf("PASS normal fee 420000\n");

    /* malicious: maxfee huge so maxfee*gaslimit wraps.
       gasPrice = 2^63, gasLimit = 21000 -> product overflows uint64 */
    n = build_legacy(tx, 0x8000000000000000ULL, 21000, 1000);
    os_clearsign_parse_evm(tx, n, &it);
    if (it.fee_limit != UINT64_MAX) {
        printf("FAIL fee wrapped to %llu instead of saturating\n",(unsigned long long)it.fee_limit); return 1; }
    printf("PASS huge maxFee saturates to UINT64_MAX (no wrap to small fee)\n");

    /* boundary: maxfee that just fits */
    n = build_legacy(tx, 1000000, 21000, 1000);
    os_clearsign_parse_evm(tx, n, &it);
    if (it.fee_limit != 21000000000ULL) { printf("FAIL boundary fee=%llu\n",(unsigned long long)it.fee_limit); return 1; }
    printf("PASS boundary fee exact\n");
    printf("\nALL ROUND-13 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
