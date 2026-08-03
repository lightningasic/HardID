/* Adversarial: PSBT with an OUTPUT map whose key 0x01 (witness_script)
 * must NOT be summed into total_in. Before the fix it was. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/psbt.h"
#include "../core/psbt.c"

static size_t put_varint(uint8_t *o, uint64_t v){ if(v<0xfd){o[0]=v;return 1;} if(v<0x10000){o[0]=0xfd;o[1]=v;o[2]=v>>8;return 3;} o[0]=0xfe;o[1]=v;o[2]=v>>8;o[3]=v>>16;o[4]=v>>24;return 5; }
static size_t put_u64le(uint8_t *o, uint64_t v){ for(int i=0;i<8;i++)o[i]=(v>>(8*i))&0xff; return 8; }
static const uint8_t SPK[22] = {0x00,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

static size_t build_tx(uint8_t *o, uint64_t amt0)
{
    size_t n=0;
    o[n++]=1;o[n++]=0;o[n++]=0;o[n++]=0;
    n+=put_varint(o+n,1);
    memset(o+n,0xaa,32); n+=32;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    n+=put_varint(o+n,0);
    o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;
    n+=put_varint(o+n,1);
    n+=put_u64le(o+n,amt0);
    n+=put_varint(o+n,sizeof SPK);
    memcpy(o+n,SPK,sizeof SPK); n+=sizeof SPK;
    o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
    return n;
}

int main(void)
{
    uint8_t tx[256], psbt[1024];
    size_t txn = build_tx(tx, 40000);
    size_t n = 0;
    memcpy(psbt+n, "psbt\xff", 5); n+=5;
    /* global map: unsigned tx */
    n+=put_varint(psbt+n,1); psbt[n++]=0x00;
    n+=put_varint(psbt+n,txn);
    memcpy(psbt+n,tx,txn); n+=txn;
    psbt[n++]=0x00; /* global sep */
    /* input map 0: witness_utxo 100000 */
    n+=put_varint(psbt+n,1); psbt[n++]=0x01;
    n+=put_varint(psbt+n, 8+sizeof SPK);
    n+=put_u64le(psbt+n, 100000);
    memcpy(psbt+n,SPK,sizeof SPK); n+=sizeof SPK;
    psbt[n++]=0x00; /* input map sep */
    /* OUTPUT map 0: key 0x01 = witness_script, big value 999999999 — this
     * must NOT pollute total_in */
    n+=put_varint(psbt+n,1); psbt[n++]=0x01;
    n+=put_varint(psbt+n, 8+sizeof SPK);
    n+=put_u64le(psbt+n, 999999999ULL);
    memcpy(psbt+n,SPK,sizeof SPK); n+=sizeof SPK;
    psbt[n++]=0x00; /* output map sep */

    os_psbt_summary s;
    if (os_psbt_parse(psbt, n, NULL, &s) != 0) { printf("parse failed (unexpected)\n"); return 1; }
    /* correct: total_in=100000, fee=100000-40000=60000 */
    if (s.total_in != 100000) { printf("FAIL: total_in polluted = %llu\n", (unsigned long long)s.total_in); return 1; }
    if (s.fee != 60000) { printf("FAIL: fee wrong = %llu\n", (unsigned long long)s.fee); return 1; }
    printf("PASS adversarial: output map did not pollute total_in/fee (fee=%llu)\n",
        (unsigned long long)s.fee);
    return 0;
}
