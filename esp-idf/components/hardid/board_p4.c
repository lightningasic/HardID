/*
 * HardID Hardware Wallet — ESP32-P4 board adapter (RNG hooks + boot hooks)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * ESP32-P4 bring-up for the hardid UI build.
 *
 * The core/ code references platform hooks that host test suites provided
 * before. This file supplies them on the ESP32-P4:
 *
 *   os_rng_hw_read_status / os_rng_hw_read_data / os_rng_hw_recover
 *     -> backed by the ESP32-P4 hardware RNG via esp_random(). The P4 RNG
 *        (same thermal Frobenius-Normal-Basis design as S3) blocks until a
 *        word is ready, so status is modelled as "ready" with no error flag.
 *
 * The seed multi-source entropy hooks (os_seed_se_trng / os_seed_se2_trng)
 * come from the dual-ACL16 composite driver (hal/se_composite.c) — each SE
 * contributes an independent TRNG draw. Do NOT redefine them here or the
 * build fails with duplicate symbols.
 *
 * Board display hooks (display_home/error) are provided by display.c; the
 * LCD init (os_board_hw_init) drives the ST7789 via board_p4.h pins.
 *
 * SECURITY NOTE: RNG hw hooks back the boot RNG self-test. In production
 * the ACL16 TRNG also feeds os_seed_generate(), so entropy is mixed between
 * the MCU and both secure elements.
 */

#include "esp_random.h"
#include "esp_log.h"
#include <stdint.h>
#include <stddef.h>

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "rng.h"
#include "boot.h"
#include "display.h"

static const char *TAG = "hardid.board";

/* ---- RNG platform hooks (drives core/rng.c) ---- */

uint32_t os_rng_hw_read_status(void)
{
	/* ESP32-P4 RNG: esp_random() blocks until a word is ready; no error
	 * flag to poll. Always report "data ready", no error. */
	return 0x1u;
}

uint32_t os_rng_hw_read_data(void)
{
	return (uint32_t)esp_random();
}

void os_rng_hw_recover(void)
{
	/* Nothing to recover on the P4 RNG; absorbing consecutive esp_random
	 * reads is sufficient. */
	(void)esp_random();
}

/* ---- Seed multi-source entropy hooks ---- */

/* In the dual-ACL16 build these come from hal/se_composite.c (each SE's
 * TRNG). In the mock-SE build there is no ACL16, so provide them from the
 * MCU hardware RNG here — same as the S3 bring-up build. Do NOT define
 * them twice for one build. */
#ifndef CONFIG_HARDID_SE_ACL16

int os_seed_se_trng(uint8_t *buf, size_t len)
{
	os_rng_fill(buf, len);
	return 0;
}

int os_seed_se2_trng(uint8_t *buf, size_t len)
{
	os_rng_fill(buf, len);
	return 0;
}

#endif /* !CONFIG_HARDID_SE_ACL16 */

/* ---- board hooks (boot.c contract). hw_init inits the LCD; display
 * hooks (display_home/error) are provided by display.c. ---- */

void os_board_hw_init(void)
{
	ESP_LOGI(TAG, "board hw init");
	/* Same shared-port story as the S3 build: HOST LINK (link_esp.c) drives
	 * the USB-Serial-JTAG port with the low-level usb_serial_jtag_* API,
	 * which requires the driver to be installed first. Install it and route
	 * the console VFS through the driver so the low-level read/write calls
	 * do not dereference a NULL driver object (panic on first USB read). */
	usb_serial_jtag_driver_config_t usj = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
	usj.rx_buffer_size = 1024;
	usj.tx_buffer_size = 1024;
	esp_err_t err = usb_serial_jtag_driver_install(&usj);
	if (err != ESP_OK)
		ESP_LOGE(TAG, "usb_serial_jtag driver install rc=%d", err);
	else
		usb_serial_jtag_vfs_use_driver();
	int rc = lcd_init();
	ESP_LOGI(TAG, "LCD init rc=%d", rc);
}

void os_board_halt(void)
{
	ESP_LOGE(TAG, "HALT");
	for (;;) { }
}