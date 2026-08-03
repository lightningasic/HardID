/* Round 7 adversarial: cooldown bypass attack. Simulates a transient host
 * compromise that tries to raise limits instantly to drain the account. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/policy.h"

static uint32_t g_now;
void os_policy_persist(const os_policy *p){(void)p;}
uint32_t os_policy_now(void){return g_now;}
#include "../core/policy.c"

int main(void){
    g_now = 1000;
    os_policy p; memset(&p,0,sizeof p);
    p.per_tx_limit = 100;
    p.window_limit = 500;
    p.window_seconds = 3600;
    p.window_start = 1000;

    /* ATTACK: compromised host instantly schedules a HUGE limit raise */
    os_policy_schedule_change(&p, g_now, 0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL);

    /* The attacker's goal: immediately auto-sign a huge tx. Must FAIL. */
    if (os_policy_authorize(&p, 1000000)) {
        printf("FAIL: cooldown bypassed — attacker signed 1000000 instantly!\n"); return 1; }
    /* active limits still the OLD ones */
    if (p.per_tx_limit != 100) { printf("FAIL: active limit mutated early\n"); return 1; }
    printf("PASS cooldown holds — instant raise blocked, old limit enforced\n");

    /* old limits still work normally during cooldown */
    if (!os_policy_authorize(&p, 100)) { printf("FAIL: legit small tx blocked\n"); return 1; }
    printf("PASS legit small tx still authorized during cooldown\n");

    /* after 24h cooldown, the pending change activates */
    g_now = 1000 + OS_POLICY_COOLDOWN_S + 1;
    os_policy_authorize(&p, 0); /* triggers activation check */
    if (p.per_tx_limit != 0xFFFFFFFFFFFFFFFFULL) {
        printf("FAIL: pending change never activated after cooldown\n"); return 1; }
    if (p.activate_after != 0) { printf("FAIL: activate_after not cleared\n"); return 1; }
    printf("PASS pending change activates after 24h cooldown\n");

    printf("\nALL ROUND-7 ADVERSARIAL TESTS PASSED\n");
    return 0;
}
