/*
 * HardID Hardware Wallet — firmware boot & main loop
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Boot order is security-critical: the RNG health test runs BEFORE any key
 * generation, and a failed entropy source halts the device visibly rather
 * than ever producing keys from a broken source.
 */

#ifndef HARDID_BOOT_H
#define HARDID_BOOT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Boot stages, in order. Each returns 0 to continue, nonzero to halt. */
typedef enum {
	OS_BOOT_STAGE_HW_INIT = 0,   /* clocks, GPIO, display */
	OS_BOOT_STAGE_RNG_TEST,      /* os_rng_self_test — MUST pass */
	OS_BOOT_STAGE_SE_INIT,       /* probe secure element */
	OS_BOOT_STAGE_ATTEST,        /* genuine-check (optional at boot) */
	OS_BOOT_STAGE_MAIN_LOOP,
} os_boot_stage;

/* Board hooks (implemented per hardware revision) */
void os_board_hw_init(void);
void os_board_display_error(const char *line1, const char *line2);
void os_board_display_home(void);
void os_board_halt(void) __attribute__((noreturn));

/* Run the boot sequence. On any failure: show error, halt (never returns
 * without reaching the main loop). Returns the first failed stage, or
 * OS_BOOT_STAGE_MAIN_LOOP when the device is ready. Exposed for tests. */
os_boot_stage os_boot_run(void);

/* The main application loop (never returns on real hardware). */
void os_main_loop(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_BOOT_H */
