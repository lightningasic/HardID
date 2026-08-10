/* Round 14: P2PKH/P2SH scriptPubKey -> correct base58 address */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/psbt.h"
#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/psbt.c"

int main(void){
    char out[80];

    /* P2PKH: scriptPubKey 76a914 <hash160> 88ac
     * hash160 = 010966776006953D5567439E5E39F86A0D273BEE
     * -> known address 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM */
    uint8_t spk[25] = {0x76,0xa9,0x14,
        0x01,0x09,0x66,0x77,0x60,0x06,0x95,0x3D,0x55,0x67,0x43,
        0x9E,0x5E,0x39,0xF8,0x6A,0x0D,0x27,0x3B,0xEE,
        0x88,0xac};
    if (!script_to_addr(spk, 25, 0, out, sizeof out)) { printf("FAIL p2pkh not decoded\n"); return 1; }
    if (strcmp(out, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM") != 0) {
        printf("FAIL p2pkh addr got %s\n", out); return 1; }
    printf("PASS P2PKH -> %s\n", out);

    /* P2SH: a914 <hash> 87, hash = f815b036d9bbbce5e9f2a00abd1bf3dc91e95510
     * -> known address 3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC (Bitcoin wiki
     *    P2SH example; cross-checked with an independent Python impl) */
    uint8_t sh[23] = {0xa9,0x14,
        0xf8,0x15,0xb0,0x36,0xd9,0xbb,0xbc,0xe5,0xe9,0xf2,
        0xa0,0x0a,0xbd,0x1b,0xf3,0xdc,0x91,0xe9,0x55,0x10,
        0x87};
    if (!script_to_addr(sh, 23, 0, out, sizeof out)) { printf("FAIL p2sh not decoded\n"); return 1; }
    if (strcmp(out, "3QJmV3qfvL9SuYo34YihAf3sRCW3qSinyC") != 0) {
        printf("FAIL p2sh addr got %s\n", out); return 1; }
    printf("PASS P2SH -> %s\n", out);

    /* invalid length / wrong opcode still falls back to hex (addr_valid false) */
    uint8_t bad[25] = {0};
    bad[0] = 0x77; /* wrong first byte */
    if (script_to_addr(bad, 25, 0, out, sizeof out)) { printf("FAIL invalid accepted\n"); return 1; }
    printf("PASS invalid script still rejected\n");

    printf("\nALL ROUND-14 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
