/* SignPolicy tests: limits, rolling window, persistence, cool-down. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/policy.h"

static uint32_t g_now;
static int g_persist_calls;
void os_policy_persist(const os_policy *p) { (void)p; g_persist_calls++; }
uint32_t os_policy_now(void) { return g_now; }

#include "../core/policy.c"

static os_policy mk(uint64_t per_tx, uint64_t win, uint32_t win_s)
{
	os_policy p;
	memset(&p, 0, sizeof p);
	p.per_tx_limit = per_tx;
	p.window_limit = win;
	p.window_seconds = win_s;
	p.window_start = g_now;
	return p;
}

int main(void)
{
	/* 1 within limits -> authorized, quota consumed */
	g_now = 1000; g_persist_calls = 0;
	os_policy p = mk(100, 500, 3600);
	if (!os_policy_authorize(&p, 100)) { printf("FAIL t1\n"); return 1; }
	if (p.window_spent != 100) { printf("FAIL t1 spent\n"); return 1; }
	printf("PASS t1 authorize within limits\n");

	/* 2 exceed per-tx -> denied, no spend */
	if (os_policy_authorize(&p, 101)) { printf("FAIL t2\n"); return 1; }
	if (p.window_spent != 100) { printf("FAIL t2 spent changed\n"); return 1; }
	printf("PASS t2 per-tx limit enforced\n");

	/* 3 exceed window -> denied */
	if (os_policy_authorize(&p, 100)) { /* spent would be 200<=500 ok */ }
	if (os_policy_authorize(&p, 100)) { /* 300 */ }
	if (os_policy_authorize(&p, 100)) { /* 400 */ }
	if (os_policy_authorize(&p, 100)) { /* 500 */ }
	if (os_policy_authorize(&p, 100)) { printf("FAIL t3 (600>500)\n"); return 1; }
	printf("PASS t3 window limit enforced\n");

	/* 4 window rolls after expiry -> quota resets */
	g_now = 1000 + 3601;
	if (!os_policy_authorize(&p, 100)) { printf("FAIL t4\n"); return 1; }
	if (p.window_spent != 100) { printf("FAIL t4 spent=%llu\n", (unsigned long long)p.window_spent); return 1; }
	printf("PASS t4 rolling window resets\n");

	/* 5 policy change enters 24h cool-down */
	g_now = 5000;
	os_policy_schedule_change(&p, g_now, 1000, 10000);
	if (!os_policy_in_cooldown(&p, g_now)) { printf("FAIL t5\n"); return 1; }
	if (os_policy_in_cooldown(&p, g_now + OS_POLICY_COOLDOWN_S)) { printf("FAIL t5 end\n"); return 1; }
	printf("PASS t5 change requires 24h cool-down\n");

	/* 6 persistence called on every mutation */
	if (g_persist_calls == 0) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 state persisted (%d writes)\n", g_persist_calls);

	printf("\nALL POLICY TESTS PASSED\n");
	return 0;
}
