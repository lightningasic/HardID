/*
 * OpenShield Hardware Wallet — firmware boot & main loop
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "boot.h"
#include "rng.h"
#include "se_driver.h"

/* Firmware override of the RNG fail-safe: show why the device died. */
void os_rng_fatal(void)
{
	os_board_display_error("RNG hardware", "failure. Do not use.");
	os_board_halt();
}

os_boot_stage os_boot_run(void)
{
	/* 1. board bring-up */
	os_board_hw_init();

	/* 2. RNG health gate — refuse to boot with broken entropy */
	if (os_rng_self_test() != 0) {
		os_board_display_error("RNG self-test", "FAILED. Do not use.");
		os_board_halt();
	}

	/* 3. secure element probe */
	if (se_active()->init() != SE_OK) {
		os_board_display_error("Secure element", "not found.");
		os_board_halt();
	}

	/* 4. genuine-check is deferred to first host pairing (optional) */

	os_board_display_home();
	return OS_BOOT_STAGE_MAIN_LOOP;
}
