/* Round 10: encode helpers must reject out-of-bounds offset, no OOB write */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/eip712.h"
#include "../core/keccak.c"
#include "../core/eip712.c"
int main(void){
    uint8_t buf[64];
    uint8_t guard[32];
    memset(buf, 0xAA, 64);
    memset(guard, 0xBB, 32);
    uint8_t addr[20]; memset(addr, 0x11, 20);

    /* valid write at offset 0 and 32 */
    if (!os_eip712_encode_address(buf, 64, 0, addr)) { printf("FAIL valid 0\n"); return 1; }
    if (!os_eip712_encode_address(buf, 64, 32, addr)) { printf("FAIL valid 32\n"); return 1; }

    /* offset 33 would overflow (33+32 > 64) — must be rejected */
    if (os_eip712_encode_address(buf, 64, 33, addr)) { printf("FAIL accepted overflow offset 33\n"); return 1; }
    /* offset beyond capacity — rejected */
    if (os_eip712_encode_address(buf, 64, 100, addr)) { printf("FAIL accepted offset 100\n"); return 1; }
    /* offset exactly at cap (no room for 32) — rejected */
    if (os_eip712_encode_address(buf, 64, 64, addr)) { printf("FAIL accepted offset == cap\n"); return 1; }
    printf("PASS overflow offsets all rejected\n");

    /* verify no OOB write happened: guard region after buf untouched.
       (place buf adjacent to guard) */
    uint8_t region[64 + 32];
    memset(region, 0xCC, sizeof region);
    uint8_t *b = region;
    os_eip712_encode_address(b, 64, 33, addr);   /* rejected, must not write */
    os_eip712_encode_address(b, 64, 100, addr);  /* rejected, must not write */
    for (int i = 64; i < 96; i++) {
        if (region[i] != 0xCC) { printf("FAIL OOB write at %d\n", i); return 1; }
    }
    printf("PASS no out-of-bounds write occurred\n");

    /* legitimate writes still land correctly */
    uint8_t ok[64]; memset(ok, 0, 64);
    os_eip712_encode_address(ok, 64, 0, addr);
    if (ok[12] != 0x11 || ok[31] != 0x11) { printf("FAIL legit write wrong\n"); return 1; }
    printf("PASS legitimate writes unaffected\n");

    printf("\nALL ROUND-10 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
