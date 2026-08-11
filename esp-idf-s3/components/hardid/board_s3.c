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

#include "driver/usb_serial_jtag.h"
#include "driver/usb_serial_jtag_vfs.h"
#include "rng.h"
#include "se_driver.h"
#include "boot.h"
#include "display.h"

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
	/* The on-board USB-Serial-JTAG port is shared between the console log
	 * VFS and the HOST LINK session (link_esp.c drives it with the low-level
	 * usb_serial_jtag_* API). The low-level API only works once the driver
	 * is installed, so bring it up here and switch the console VFS over to
	 * the driver-backed path — otherwise link_esp.c dereferences a NULL
	 * driver object and panics on the first USB read. */
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