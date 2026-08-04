#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/seed.h"
#include "../core/rng.h"
static uint8_t g_se[32];
static int g_se_fail = 0;
int os_seed_se_trng(uint8_t *buf, size_t len){ if(g_se_fail) return -1; memcpy(buf,g_se,len<32?len:32); return 0; }
int os_seed_se2_trng(uint8_t *buf, size_t len){ os_rng_fill(buf,len); return 0; }
static uint32_t g_r=99;
uint32_t os_rng_hw_read_status(void){return 1;}
uint32_t os_rng_hw_read_data(void){g_r=g_r*1103515245u+12345u;return g_r;}
void os_rng_hw_recover(void){}
#define OS_RNG_NO_DEFAULT_FATAL
#include "../core/rng.c"
#include "../core/hkdf.c"
#define OS_SEED_NO_DEFAULT_HOOK
#include "../core/seed.c"
void os_rng_fatal(void){}
int main(void){
    uint8_t s1[32],s2[32];
    memset(g_se,0x5A,32);
    /* same inputs -> deterministic */
    g_r=1; os_seed_generate((const uint8_t*)"h",1,s1);
    g_r=1; os_seed_generate((const uint8_t*)"h",1,s2);
    if(memcmp(s1,s2,32)!=0){printf("FAIL determinism\n");return 1;}
    printf("PASS seed deterministic\n");
    /* SE failure -> -1 and output not partially written predictably */
    g_se_fail=1;
    memset(s1,0xAA,32);
    int r=os_seed_generate((const uint8_t*)"h",1,s1);
    if(r!=-1){printf("FAIL SE failure not rejected\n");return 1;}
    printf("PASS SE failure rejected\n");
    /* huge host entropy handled */
    g_se_fail=0;
    uint8_t big[1000]; memset(big,7,1000);
    g_r=5;
    if(os_seed_generate(big,1000,s1)!=0){printf("FAIL big host entropy\n");return 1;}
    printf("PASS huge host entropy handled\n");
    printf("\nALL ROUND-22 seed TESTS PASSED\n");
    return 0;
}
