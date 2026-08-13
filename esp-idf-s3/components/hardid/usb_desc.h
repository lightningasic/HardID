/*
 * HardID Hardware Wallet — USB bring-up API (F3 transport)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * usb_desc.c: exposes the composite descriptor data that esp_tinyusb 2.x
 * binds through tinyusb_desc_config_t.
 * usb_esp.c: owns the driver install + CDC linkproto carrier.
 */

#ifndef HARDID_USB_DESC_H
#define HARDID_USB_DESC_H

#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "tusb.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Descriptor data (usb_desc.c) ---- */
const tusb_desc_device_t *hardid_usb_device_desc(void);
const uint8_t *hardid_usb_fs_config_desc(void);
const uint8_t *hardid_usb_hid_report_desc(void);
const char **hardid_usb_strings(int *count);

/* ---- Driver bring-up + CDC link bridge (usb_esp.c) ---- */
esp_err_t hardid_usb_init(void);

/* Read a single byte from the linkproto CDC carrier.
 * Returns 1 on a byte, 0 on timeout (timeout_ticks == portMAX_DELAY waits). */
int hardid_usb_read_byte(uint8_t *b, uint32_t timeout_ticks);

/* Write a block to the linkproto CDC carrier. */
void hardid_usb_write(const uint8_t *buf, size_t len, uint32_t timeout_ticks);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_USB_DESC_H */
