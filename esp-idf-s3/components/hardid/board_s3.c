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

#include "usb_desc.h"
#include "rng.h"
#include "se_driver.h"
#include "boot.h"
#include "display.h"

void os_entropy_force_link(void);   /* entropy_s3.c: pull strong os_seed_phys_extra in */

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

/* ---- board hooks (boot.c contract). hw_init inits the LCD; display
 * hooks (display_home/error) are provided by display.c. ---- */

void os_board_hw_init(void)
{
	ESP_LOGI(TAG, "board hw init");
	os_entropy_force_link();   /* ensure the physical-entropy hook is linked */
	/* F3 (design §1.1): the USB-OTG port replaces the ROM USB-Serial-JTAG
	 * console with a TinyUSB composite (CTAPHID HID + CDC-ACM). The
	 * linkproto HOST LINK carrier and console move to the composite CDC;
	 * touch-inject over the old JTAG console is no longer reachable. */
	/* USB/USJ FIX: esp_perip_clk_init (startup) disabled the USJ clock
	 * (perip_clk_en1.usb_device_clk_en bit10) and pad, so every USJ conf0
	 * read returned 0 and every write was ignored (clock-gated). Yet the
	 * host keeps seeing 303a:1001 because the USJ physical link (D+ pullup)
	 * is held by the PHY hardware state machine while enumerated, so USJ
	 * keeps the shared FSLS PHY and the OTG never gets it (the PHY mux
	 * register switches to OTG but the hardware ignores it while USJ holds
	 * the PHY). Fix: re-enable the USJ clock, then take SW control of the
	 * pull resistors and disable the pad -> D+ pullup drops -> host sees a
	 * disconnect -> PHY is physically freed for the OTG. */
	*(volatile uint32_t *)0x600C001C |= 0x0400u;   /* perip_clk_en1.usb_device_clk_en = 1 */
	__asm__ __volatile__("memw");
	*(volatile uint32_t *)0x60038018 = 0x0100u;    /* conf0: pad_pull_override=1, dp_pullup=0, usb_pad_enable=0 */
	__asm__ __volatile__("memw");
	esp_err_t usb_rc = hardid_usb_init();
	if (usb_rc != ESP_OK)
		ESP_LOGE(TAG, "hardid_usb_init rc=%d", usb_rc);
	ESP_LOGI(TAG, "USB init rc=%d", (int)usb_rc);
	int rc = lcd_init();
	ESP_LOGI(TAG, "LCD init rc=%d", rc);
}

void os_board_halt(void)
{
	ESP_LOGE(TAG, "HALT");
	for (;;) { }
}