/* Host-side verification for OpenShield RNG core.
 * Scripts the platform hooks to emulate healthy/stuck/error hardware. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../core/rng.h"

/* ---- fake platform ---- */
static uint32_t script[4096];
static int script_len, script_pos;
static int error_flag;       /* 1 => status reports error bit */
static int recover_calls;
int g_fatal_calls;

uint32_t os_rng_hw_read_status(void)
{
	if (error_flag) return 0x2u;              /* error bit set */
	if (script_pos < script_len) return 0x1u; /* data ready */
	return 0;                                  /* no data */
}
uint32_t os_rng_hw_read_data(void)
{
	return script_pos < script_len ? script[script_pos++] : 0;
}
void os_rng_hw_recover(void)
{
	recover_calls++;
	error_flag = 0;
}
void os_rng_fatal(void) { g_fatal_calls++; for(;;){} }

static void feed(const uint32_t *v, int n)
{
	memcpy(script, v, n * sizeof(uint32_t));
	script_len = n; script_pos = 0;
}
static void reset(void)
{
	script_len = script_pos = 0;
	error_flag = 0; recover_calls = 0; g_fatal_calls = 0;
}

/* include the implementation directly for hook access */
#define OS_RNG_NO_DEFAULT_FATAL
#include "../core/rng.c"

int main(void)
{
	/* 1 healthy self-test */
	reset();
	uint32_t a[8] = {1,2,3,4,5,6,7,8};
	feed(a, 8);
	if (os_rng_self_test() != 0) { printf("FAIL t1\n"); return 1; }
	printf("PASS t1 healthy self-test\n");

	/* 2 stuck-at -> rejected */
	reset();
	uint32_t b[8] = {9,9,9,9,9,9,9,9};
	feed(b, 8);
	if (os_rng_self_test() == 0) { printf("FAIL t2\n"); return 1; }
	printf("PASS t2 stuck-at rejected\n");

	/* 3 all-zero -> rejected */
	reset();
	uint32_t c[8] = {0};
	feed(c, 8);
	if (os_rng_self_test() == 0) { printf("FAIL t3\n"); return 1; }
	printf("PASS t3 all-zero rejected\n");

	/* 4 u32 distinct */
	reset();
	uint32_t d[4] = {100,200,300,400};
	feed(d, 4);
	uint32_t x = os_rng_u32(), y = os_rng_u32();
	if (x == y || g_fatal_calls) { printf("FAIL t4\n"); return 1; }
	printf("PASS t4 u32 distinct\n");

	/* 5 error flag -> recover then read */
	reset();
	error_flag = 1;
	uint32_t e[2] = {7,8};
	feed(e, 2);
	os_rng_u32();
	if (recover_calls == 0) { printf("FAIL t5 no recovery\n"); return 1; }
	printf("PASS t5 error recovered (%d recoveries)\n", recover_calls);

	/* 6 uniform range */
	reset();
	uint32_t f[64];
	for (int i = 0; i < 64; i++) f[i] = 1000 + i * 2654435761u;
	feed(f, 64);
	int ok = 1;
	for (int i = 0; i < 50; i++) {
		if (script_pos >= script_len) feed(f, 64);
		if (os_rng_uniform(9) >= 9) { ok = 0; break; }
	}
	if (!ok) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 uniform range\n");

	printf("\nALL RNG HOST TESTS PASSED\n");
	return 0;
}
