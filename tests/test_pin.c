/* PIN backoff tests: exponential growth, cap, persistence, no self-destruct. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/pin.h"

/* fake SE storage + time */
static os_pin_state g_st;
static uint32_t g_now;
static bool g_pin_ok;
static bool g_duress_pin;

void os_pin_load_state(os_pin_state *st) { *st = g_st; }
void os_pin_save_state(const os_pin_state *st) { g_st = *st; }
uint32_t os_pin_now(void) { return g_now; }
bool os_pin_hw_verify(const uint8_t *pin, size_t len, bool *is_duress)
{
	(void)pin; (void)len;
	if (g_pin_ok) { if (is_duress) *is_duress = false; return true; }
	if (g_duress_pin) { if (is_duress) *is_duress = true; return true; }
	return false;
}

#include "../core/pin.c"

int main(void)
{
	/* 1 backoff schedule: 1,2,4,8,16... capped at 24h */
	uint32_t expect[] = {1,2,4,8,16,32};
	for (uint32_t i = 0; i < 6; i++)
		if (os_pin_backoff_seconds(i+1) != expect[i]) { printf("FAIL t1 %u\n", i); return 1; }
	if (os_pin_backoff_seconds(100) != OS_PIN_BACKOFF_MAX_S) { printf("FAIL t1 cap\n"); return 1; }
	printf("PASS t1 backoff schedule + cap\n");

	/* 2 failed attempt arms backoff, persists */
	g_now = 1000; g_pin_ok = false; g_duress_pin = false;
	memset(&g_st, 0, sizeof g_st);
	uint32_t w = os_pin_attempt((const uint8_t *)"0000", 4, NULL);
	if (w != 1 || g_st.fail_count != 1 || g_st.lock_until != 1001) { printf("FAIL t2\n"); return 1; }
	printf("PASS t2 first failure arms 1s backoff\n");

	/* 3 attempt during backoff is refused without verifying */
	g_now = 1000; /* still before lock_until=1001 */
	g_pin_ok = true; /* even correct PIN during lock is refused */
	w = os_pin_attempt((const uint8_t *)"1234", 4, NULL);
	if (w != 1) { printf("FAIL t3 (should report remaining 1)\n"); return 1; }
	if (g_st.fail_count != 1) { printf("FAIL t3 (fail_count changed during lock)\n"); return 1; }
	printf("PASS t3 locked-out attempt refused, no verify\n");

	/* 4 backoff expiry -> verify again, success resets */
	g_now = 1001;
	w = os_pin_attempt((const uint8_t *)"1234", 4, NULL);
	if (w != 0 || g_st.fail_count != 0) { printf("FAIL t4\n"); return 1; }
	printf("PASS t4 success after backoff resets counter\n");

	/* 5 repeated failures escalate: 2nd failure waits 2s */
	g_now = 2000; g_pin_ok = false;
	os_pin_attempt((const uint8_t *)"x", 1, NULL); /* fail_count=1, wait1 */
	g_now = 2001;
	w = os_pin_attempt((const uint8_t *)"x", 1, NULL); /* fail_count=2, wait2 */
	if (w != 2 || g_st.fail_count != 2) { printf("FAIL t5 w=%u fc=%u\n", w, g_st.fail_count); return 1; }
	printf("PASS t5 escalation to 2s\n");

	/* 6 no self-destruct: many failures never wipe, just longer waits */
	memset(&g_st, 0, sizeof g_st); g_now = 0;
	for (int i = 0; i < 50; i++) {
		g_now += os_pin_backoff_seconds(g_st.fail_count);
		os_pin_attempt((const uint8_t *)"x", 1, NULL);
	}
	if (g_st.fail_count != 50) { printf("FAIL t6 fc=%u\n", g_st.fail_count); return 1; }
	printf("PASS t6 50 failures, no wipe, fail_count=%u (max backoff)\n", g_st.fail_count);

	/* 7 duress PIN matches -> is_duress set, no fail */
	g_now = 100000; memset(&g_st, 0, sizeof g_st);
	g_duress_pin = true; g_pin_ok = false;
	bool d = false;
	w = os_pin_attempt((const uint8_t *)"duress", 6, &d);
	if (w != 0 || !d) { printf("FAIL t7\n"); return 1; }
	printf("PASS t7 duress PIN opens decoy view\n");

	printf("\nALL PIN TESTS PASSED\n");
	return 0;
}
