/* Round 5 adversarial: input validation */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/bip39.h"
#include "../core/pin.h"
#include "../core/sha512.h"

#include "../core/sha512.c"
#include "../core/hkdf.c"
#include "../core/bip39.c"

static os_pin_state g_st; static uint32_t g_now; static bool g_pin_ok;
void os_pin_load_state(os_pin_state *st){*st=g_st;}
void os_pin_save_state(const os_pin_state *st){g_st=*st;}
uint32_t os_pin_now(void){return g_now;}
bool os_pin_hw_verify(const uint8_t*p,size_t l,bool*d){(void)p;(void)l;(void)d;return g_pin_ok;}
#include "../core/pin.c"

int main(void){
    uint8_t rec[32];

    /* bip39: 25th word must be REJECTED, not silently truncated */
    const char *m25 = "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about "
        "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about extra";
    if (os_bip39_mnemonic_to_entropy(m25, rec, sizeof rec) != 0) {
        printf("FAIL bip39: 25-word input accepted\n"); return 1; }
    printf("PASS bip39 rejects 25th word\n");

    /* bip39: trailing non-space garbage rejected */
    const char *mg = "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about xyz";
    if (os_bip39_mnemonic_to_entropy(mg, rec, sizeof rec) != 0) {
        printf("FAIL bip39: trailing garbage accepted\n"); return 1; }
    printf("PASS bip39 rejects trailing garbage\n");

    /* bip39: valid 12-word still works after fix */
    const char *ok = "abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon abandon abandon about";
    if (os_bip39_mnemonic_to_entropy(ok, rec, sizeof rec) != 16) {
        printf("FAIL bip39: valid 12-word rejected\n"); return 1; }
    printf("PASS bip39 valid 12-word still accepted\n");

    /* pin: out-of-range length never reaches verifier, counts as failure */
    g_now=1000; g_pin_ok=true; memset(&g_st,0,sizeof g_st);
    uint8_t short_pin[2]={'1','2'};
    uint32_t w = os_pin_attempt(short_pin, 2, NULL);  /* len 2 < MIN 4 */
    if (w == 0 && g_st.fail_count == 0) {
        printf("FAIL pin: short PIN bypassed failure accounting\n"); return 1; }
    if (g_st.fail_count != 1) {
        printf("FAIL pin: out-of-range not counted as failure (fc=%u)\n", g_st.fail_count); return 1; }
    printf("PASS pin out-of-range counts as failure, no verifier call\n");

    /* pin: max-length boundary works */
    g_now=2000; g_pin_ok=true; memset(&g_st,0,sizeof g_st);
    uint8_t maxpin[OS_PIN_MAX_LEN]; memset(maxpin,'5',OS_PIN_MAX_LEN);
    w = os_pin_attempt(maxpin, OS_PIN_MAX_LEN, NULL);
    if (w != 0) { printf("FAIL pin: max-length valid PIN rejected (w=%u)\n", w); return 1; }
    printf("PASS pin max-length boundary accepted\n");

    printf("\nALL ROUND-5 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
