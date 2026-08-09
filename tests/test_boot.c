/* Boot sequence tests: RNG gate, SE probe, halt-on-failure. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <setjmp.h>
#include "../core/boot.h"
#include "../core/se_driver.h"

/* ---- board hooks (record calls; halt longjmps to simulate noreturn) ---- */
static int g_halted;
static char g_err1[32], g_err2[32];
static int g_hw_init, g_home;
static jmp_buf g_halt_jmp;

void os_board_hw_init(void) { g_hw_init++; }
void os_board_display_error(const char *l1, const char *l2)
{
	strncpy(g_err1, l1, 31); strncpy(g_err2, l2, 31);
}
void os_board_display_home(void) { g_home++; }
void os_board_halt(void) { g_halted++; longjmp(g_halt_jmp, 1); }

/* ---- RNG fake ---- */
static int g_rng_healthy = 1;
uint32_t os_rng_hw_read_status(void) { return g_rng_healthy ? 1 : 0; }
static uint32_t g_r = 12345;
uint32_t os_rng_hw_read_data(void) { g_r = g_r * 1103515245u + 12345u; return g_r; }
void os_rng_hw_recover(void) {}

#define OS_RNG_NO_DEFAULT_FATAL
#include "../core/rng.c"
#include "../core/se_mock.c"
#include "../core/sha512.c"
#include "../core/boot.c"

static void reset_all(void)
{
	g_halted = 0; g_hw_init = 0; g_home = 0;
	g_err1[0] = g_err2[0] = 0;
	g_rng_healthy = 1;
	se_mock_reset();
}

int main(void)
{
	/* 1 healthy boot reaches main loop */
	reset_all();
	if (os_boot_run() != OS_BOOT_STAGE_MAIN_LOOP) { printf("FAIL t1\n"); return 1; }
	if (!g_hw_init || !g_home || g_halted) { printf("FAIL t1 flags\n"); return 1; }
	printf("PASS t1 healthy boot\n");

	/* 2 RNG unhealthy -> halt with error, never reach home */
	reset_all();
	g_rng_healthy = 0;
	if (setjmp(g_halt_jmp) == 0)
		os_boot_run(); /* halts inside via longjmp */
	if (!g_halted) { printf("FAIL t2 no halt\n"); return 1; }
	if (g_home) { printf("FAIL t2 reached home\n"); return 1; }
	if (strstr(g_err1, "RNG") == NULL) { printf("FAIL t2 err=%s\n", g_err1); return 1; }
	printf("PASS t2 RNG failure halts with error ('%s %s')\n", g_err1, g_err2);

	/* 3 SE present (mock init returns OK) */
	reset_all();
	if (se_active()->init() != SE_OK) { printf("FAIL t3\n"); return 1; }
	printf("PASS t3 SE probe\n");

	printf("\nALL BOOT TESTS PASSED\n");
	return 0;
}
