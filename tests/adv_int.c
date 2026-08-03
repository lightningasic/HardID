#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/policy.h"
#include "../core/pin.h"

static uint32_t g_now; static os_policy g_p; static os_pin_state g_st;
void os_policy_persist(const os_policy *p){(void)p;}
uint32_t os_policy_now(void){return g_now;}
void os_pin_load_state(os_pin_state *st){*st=g_st;}
void os_pin_save_state(const os_pin_state *st){g_st=*st;}
uint32_t os_pin_now(void){return g_now;}
bool os_pin_hw_verify(const uint8_t*p,size_t l,bool*d){(void)p;(void)l;(void)d;return false;}

#include "../core/policy.c"
#include "../core/pin.c"

int main(void){
    /* policy: spent+amount overflow must NOT bypass */
    g_now=1000;
    os_policy p; memset(&p,0,sizeof p);
    p.per_tx_limit=1000; p.window_limit=1000; p.window_seconds=3600;
    p.window_spent=0xFFFFFFFFFFFFFFF0ULL; /* near u64 max, corrupted */
    p.window_start=1000;
    if(os_policy_authorize(&p, 100)){ printf("FAIL policy: overflow allowed spend\n"); return 1; }
    printf("PASS policy overflow fails closed\n");

    /* pin: lock_until wraparound must not bypass backoff */
    g_now=0xFFFFFFF0u;
    memset(&g_st,0,sizeof g_st); g_st.fail_count=0;
    uint32_t w=os_pin_attempt((const uint8_t*)"x",1,NULL);
    /* backoff should be 1s but now+1 wraps to 0xFFFFFFF1 -> wait should be 1 */
    if(g_st.lock_until < g_now){ printf("FAIL pin: lock_until wrapped to %u (now=%u)\n", g_st.lock_until, g_now); return 1; }
    printf("PASS pin lock_until no wraparound (lock_until=%u)\n", g_st.lock_until);
    return 0;
}
