/*
 * HardID Hardware Wallet — TinyUSB composite bring-up (CTAPHID + CDC)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Milestone F3 on-board glue: install the esp_tinyusb 2.x driver with the
 * composite descriptors from usb_desc.c and bring up the CDC-ACM interface
 * that carries the linkproto console (HOST LINK, link_esp.c).
 *
 *   USB-OTG (GPIO19/20)  ->  TinyUSB composite:
 *       interface 0/1 : CDC-ACM (linkproto + console)
 *       interface 2   : HID 0xF1D0 CTAPHID (FIDO, fido_esp.c)
 *
 * The FIDO HID class driver callbacks (tud_hid_*) are provided by the
 * application (fido_esp.c); the descriptor callbacks are provided by
 * esp_tinyusb 2.x itself (descriptors_control.c) and bound through the
 * tinyusb_desc_config_t given here.
 *
 * NOTE (USB 双控制器互斥): ESP32-S3 shares GPIO19/20 between USB-OTG and
 * USB-Serial-JTAG. Once TinyUSB takes over the OTG port, the ROM
 * USB-Serial-JTAG console used by board_s3.c / touch inject is no longer
 * reachable — the console VFS moves to the composite CDC (see §1.1 of the
 * FIDO design doc). This file owns that hand-off.
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_err.h"
#include "tinyusb.h"
#include "tinyusb_cdc_acm.h"
#include "tinyusb_console.h"

#include "usb_desc.h"

static const char *TAG = "hardid.usb";

/* Linkproto carrier: CDC-ACM interface 0 (first serial port). */
#define LINK_CDC_ITF   TINYUSB_CDC_ACM_0

static SemaphoreHandle_t s_rx_lock;

/* ---- CDC RX event: packetize raw bytes for the link screen ---- */

static void cdc_rx_cb(int itf, cdcacm_event_t *event)
{
	(void)itf;
	if (event->type == CDC_EVENT_RX)
		xSemaphoreGive(s_rx_lock);
}

/* ---- Public bridge API for link_esp.c ---- */

int hardid_usb_read_byte(uint8_t *b, uint32_t timeout_ticks)
{
	if (s_rx_lock == NULL)
		return 0;   /* USB not initialised: no carrier to read from */
	size_t got = 0;
	for (;;) {
		size_t n = 0;
		esp_err_t rc = tinyusb_cdcacm_read(LINK_CDC_ITF, b, 1, &n);
		if (rc == ESP_OK && n == 1) {
			got = 1;
			break;
		}
		if (xSemaphoreTake(s_rx_lock, pdMS_TO_TICKS(1)) != pdTRUE)
			break;   /* no data within the poll budget */
		if (timeout_ticks != portMAX_DELAY)
			if (timeout_ticks-- == 0)
				break;
	}
	return (int)got;
}

void hardid_usb_write(const uint8_t *buf, size_t len, uint32_t timeout_ticks)
{
	size_t off = 0;
	while (off < len) {
		size_t n = tinyusb_cdcacm_write_queue(LINK_CDC_ITF,
		                                      buf + off, len - off);
		if (n > 0) {
			off += n;
			continue;
		}
		tinyusb_cdcacm_write_flush(LINK_CDC_ITF, timeout_ticks);
		if (timeout_ticks != portMAX_DELAY)
			if (timeout_ticks-- == 0)
				break;
		vTaskDelay(pdMS_TO_TICKS(1));
	}
	tinyusb_cdcacm_write_flush(LINK_CDC_ITF, timeout_ticks);
}

/* ---- Driver bring-up ---- */

esp_err_t hardid_usb_init(void)
{
	s_rx_lock = xSemaphoreCreateBinary();
	if (s_rx_lock == NULL)
		return ESP_ERR_NO_MEM;

	/* Descriptors from usb_desc.c (device, FS config, strings). */
	int nstr = 0;
	const char **strs = hardid_usb_strings(&nstr);

	const tinyusb_desc_config_t desc = {
		.device            = hardid_usb_device_desc(),
		.qualifier         = NULL,
		.string            = strs,
		.string_count      = nstr,
		.full_speed_config = hardid_usb_fs_config_desc(),
		.high_speed_config = NULL,
	};

	tinyusb_config_t cfg = {
		.port = TINYUSB_PORT_FULL_SPEED_0,
		.phy = {
			.skip_setup      = false,
			.self_powered    = false,
			.vbus_monitor_io = -1,
		},
		.task = {
			.size     = 4096,
			.priority = 5,
			.xCoreID  = 1,
		},
		.descriptor = desc,
		.event_cb   = NULL,
		.event_arg  = NULL,
	};

	esp_err_t rc = tinyusb_driver_install(&cfg);
	if (rc != ESP_OK) {
		ESP_LOGE(TAG, "tinyusb_driver_install rc=%d", rc);
		return rc;
	}

	/* CDC-ACM for the linkproto carrier. */
	const tinyusb_config_cdcacm_t cdc_cfg = {
		.cdc_port                  = LINK_CDC_ITF,
		.callback_rx               = cdc_rx_cb,
		.callback_rx_wanted_char   = NULL,
		.callback_line_state_changed = NULL,
		.callback_line_coding_changed = NULL,
	};
	rc = tinyusb_cdcacm_init(&cdc_cfg);
	if (rc != ESP_OK) {
		ESP_LOGE(TAG, "tinyusb_cdcacm_init rc=%d", rc);
		return rc;
	}

	/* The board exposes no UART; the ROM USB-Serial-JTAG console died with
	 * the USB-OTG hand-off (design §1.1). Redirect the console VFS to the
	 * composite CDC so ESP_LOG stays visible on the host (e.g. /dev/ttyACM0
	 * / idf.py monitor). CONFIG_ESP_CONSOLE_USB_CDC is mutually exclusive
	 * with TinyUSB, so this is the supported path. */
	rc = tinyusb_console_init((int)LINK_CDC_ITF);
	if (rc != ESP_OK)
		ESP_LOGE(TAG, "tinyusb_console_init rc=%d", rc);

	ESP_LOGI(TAG, "TinyUSB composite up (CTAPHID HID + CDC-ACM link)");
	return ESP_OK;
}
