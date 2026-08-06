/*
 * HardID Hardware Wallet — ESP32-S3 board adapter (RNG + entropy hooks)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Waveshare ESP32-S3-Touch-LCD-2 bring-up for the orphaned-core build.
 *
 * The core/ code references three platform hooks that only the host test
 * suites provided before. This file supplies them on the ESP32-S3:
 *
 *   os_rng_hw_read_status / os_rng_hw_read_data / os_rng_hw_recover
 *     -> backed by the ESP32-S3 hardware RNG via esp_random().
 *        ESP32-S3's RNG is a continuous thermal/Frobenius-Normal-Basis RNG;
 *        esp_random() blocks until a word is ready, so status is modelled as
 *        "ready" (bit0=1) with no recoverable error flag.
 *
 *   os_seed_se_trng / os_seed_se2_trng
 *     -> two independent entropy sources for os_seed_generate(). In this
 *        mock-SE bring-up build BOTH are fed from the MCU RNG so real
 *        hardware entropy is always mixed in (the ACL16 TRNG hooks are used
 *        in the production dual-ACL16 build).
 */

#include "esp_random.h"
#include "esp_log.h"
#include <stdint.h>
#include <stddef.h>

#include "rng.h"
#include "se_driver.h"
#include "boot.h"

static const char *TAG = "hardid.board";

/* ---- RNG platform hooks (drives core/rng.c) ---- */

uint32_t os_rng_hw_read_status(void)
{
	/* ESP32-S3 RNG: esp_random() blocks until a word is ready; no error
	 * flag to poll. Always report "data ready", no error. */
	return 0x1u;
}

uint32_t os_rng_hw_read_data(void)
{
	return (uint32_t)esp_random();
}

void os_rng_hw_recover(void)
{
	/* Nothing to recover on the S3 RNG; absorbing consecutive esp_random
	 * reads is sufficient. */
	(void)esp_random();
}

/* ---- Seed multi-source entropy hooks (drives core/seed.c) ---- */

int os_seed_se_trng(uint8_t *buf, size_t len)
{
	/* In the mock build there is no separate secure element TRNG behind
	 * SE1, so source 1 comes from the same calibrated MCU hardware RNG. */
	os_rng_fill(buf, len);
	return 0;
}

int os_seed_se2_trng(uint8_t *buf, size_t len)
{
	/* Source 2: an independent draw from the MCU hardware RNG. In the
	 * production dual ACL16 build this is SE2's TRNG. */
	os_rng_fill(buf, len);
	return 0;
}

/* ---- board hooks (boot.c contract). Display is not wired yet on the
 * bring-up port; report over UART. ---- */

void os_board_hw_init(void)
{
	ESP_LOGI(TAG, "board hw init (no display wired; WD boot OK)");
}

void os_board_display_error(const char *line1, const char *line2)
{
	ESP_LOGE(TAG, "BOARD ERROR: %s %s", line1 ? line1 : "", line2 ? line2 : "");
}

void os_board_display_home(void)
{
	ESP_LOGI(TAG, "home screen (display TBD)");
}

void os_board_halt(void)
{
	ESP_LOGE(TAG, "HALT");
	for (;;) { }
}