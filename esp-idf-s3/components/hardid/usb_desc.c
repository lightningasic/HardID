/*
 * HardID Hardware Wallet — TinyUSB composite descriptors (CTAPHID + CDC)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Milestone F3: expose the ESP32-S3 native USB (USB-OTG) as a TinyUSB
 * composite device so FIDO (CTAP2 over HID) and the existing linkproto
 * console can coexist on one bus — see docs/09_FIDO设计文档.md §1.1/§2.
 *
 *   - FIDO HID interface: usage page 0xF1D0 (FIDO Alliance), usage 0x01
 *     (CTAP HID), report id 1, 64-byte report = one CTAPHID packet
 *     (core/fido_ctaphid.h: cid(4) | cmd(1,0x80 set) | bcnt(2) | data).
 *     No boot protocol; 64-byte IN + OUT interrupt reports.
 *   - CDC interface: standard ACM console + linkproto carrier so HOST LINK
 *     (link_esp.c) keeps working after the transport move (design §§2/§10).
 *
 * Descriptors are hand-laid raw bytes (the same style as the TinyUSB
 * samples) so the layout is unambiguous and self-auditable here even
 * though this file cannot be compiled on the offline dev box.
 *
 * BUILD NOTE (environment): this file compiles only with the espressif
 * esp_tinyusb managed component (v5.3 has it as a registry component, not
 * bundled). The CI box at build time had no network to fetch it and no
 * USB hardware, so this ship is the on-board half of F3 that cannot be
 * compiled/verified here — the transport layer (core/fido_ctaphid.c +
 * tests/test_ctaphid_net.c) IS fully host-verified.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "tusb.h"
#include "device/usbd.h"

#define HARDID_USB_VID  0x1209       /* pid.codes (placeholder) */
#define HARDID_USB_PID  0xF1D0

/* Interface & endpoint numbers (match the raw config descriptor). */
enum {
	ITF_CDC_CTRL = 0,
	ITF_CDC_DATA,
	ITF_FIDO_HID,
	ITF_COUNT,
};
enum {
	EP_CDC_NOTIFY = 0x81,
	EP_CDC_OUT    = 0x03,
	EP_CDC_IN     = 0x82,
	EP_FIDO_IN    = 0x84,
	EP_FIDO_OUT   = 0x05,
};

/* ---- Device descriptor ---- */
static const tusb_desc_device_t s_dev = {
	.bLength            = sizeof(tusb_desc_device_t),
	.bDescriptorType    = TUSB_DESC_DEVICE,
	.bcdUSB             = 0x0200,
	.bDeviceClass       = TUSB_CLASS_MISC,
	.bDeviceSubClass    = MISC_SUBCLASS_COMMON,
	.bDeviceProtocol    = MISC_PROTOCOL_IAD,
	.bMaxPacketSize0    = 64,
	.idVendor           = HARDID_USB_VID,
	.idProduct          = HARDID_USB_PID,
	.bcdDevice          = 0x0100,
	.iManufacturer      = 1,
	.iProduct           = 2,
	.iSerialNumber      = 3,
	.bNumConfigurations = 1,
};

/* ---- Configuration descriptor (raw bytes, composite) ----
 *
 *  config header | IAD (CDC ctrl+data) | CDC-ACM control iface |
 *  functional descs | notify EP | CDC data iface | bulk EP out/in |
 *  FIDO HID iface | HID descriptor | 31-byte report descriptor |
 *  FIDO IN/OUT EPs
 */
enum {
	CONFIG_LEN = 138,
	HID_REPORT_DESC_LEN = 31,
};

static const uint8_t s_config[CONFIG_LEN] = {
	/* Configuration header */
	0x09, 0x02, 0x8A, 0x00,  /* bLength, type, wTotalLength = 138 (LE) */
	0x03,                    /* bNumInterfaces */
	0x01,                    /* bConfigurationValue */
	0x00,                    /* iConfiguration */
	0x80,                    /* bmAttributes: bus powered */
	0x32,                    /* bMaxPower: 100 mA (units of 2 mA) */
	/* IAD: associate interfaces 0..1 (CDC) */
	0x08, 0x0B, 0x00, 0x02, 0x02, 0x02, 0x01, 0x00,
	/* CDC control interface (ACM) */
	0x09, 0x04, 0x00, 0x00, 0x01, 0x02, 0x02, 0x01, 0x00,
	/* CDC functional: Header */
	0x05, 0x24, 0x00, 0x10, 0x01,
	/* CDC functional: Call Management */
	0x05, 0x24, 0x01, 0x00, 0x01,
	/* CDC functional: ACM */
	0x04, 0x24, 0x02, 0x02,
	/* CDC functional: Union */
	0x05, 0x24, 0x06, 0x00, 0x01,
	/* Notify EP (interrupt IN) */
	0x07, 0x05, 0x81, 0x03, 0x08, 0x00, 0x10,
	/* CDC data interface */
	0x09, 0x04, 0x01, 0x00, 0x02, 0x0A, 0x00, 0x00, 0x00,
	/* Bulk out / in */
	0x07, 0x05, 0x03, 0x02, 0x40, 0x00, 0x00,
	0x07, 0x05, 0x82, 0x02, 0x40, 0x00, 0x00,
	/* FIDO HID interface */
	0x09, 0x04, 0x02, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
	/* HID descriptor: 1 report descriptor of 31 bytes */
	0x09, 0x21, 0x01, 0x01, 0x00, 0x01, 0x22, 0x1F, 0x00,
	/* ---- CTAP-HID report descriptor (31 bytes) ----
	 * Usage Page (FIDO Alliance 0xF1D0) | Usage (CTAPHID 0x01) |
	 * Collection (Application) | Report ID (1) | 64-byte IN/OUT data */
	0x05, 0xD0, 0xF1,                     /* Usage Page (FIDO)          */
	0x09, 0x01,                           /* Usage (CTAPHID)            */
	0xA1, 0x01,                           /* Collection (Application)   */
	0x85, 0x01,                           /*   Report ID (1)            */
	0x09, 0x20,                           /*   Usage (Data In)          */
	0x15, 0x00, 0x26, 0xFF, 0x00,         /*   Logical Min 0 Max 255    */
	0x95, 0x40, 0x75, 0x08,               /*   Count 64, size 8         */
	0x81, 0x02,                           /*   Input (Data, Var, Abs)   */
	0x09, 0x21,                           /*   Usage (Data Out)         */
	0x95, 0x40, 0x75, 0x08,               /*   Count 64, size 8         */
	0x91, 0x02,                           /*   Output (Data, Var, Abs)  */
	0xC0,                                 /* End Collection             */
	/* FIDO interrupt IN / OUT endpoint */
	0x07, 0x05, 0x84, 0x03, 0x40, 0x00, 0x01,
	0x07, 0x05, 0x05, 0x03, 0x40, 0x00, 0x01,
};

/* ---- String descriptors ---- */
static const char *const s_str[] = {
	[0] = "HardID",
	[1] = "LightningASIC",
	[2] = "HardID Secure Wallet",
	[3] = "000000000001",
};

static uint16_t s_str_buf[64];

const tusb_desc_device_t *tud_descriptor_device_cb(void)
{
	return &s_dev;
}

const uint8_t *tud_descriptor_configuration_cb(uint8_t index)
{
	(void)index;
	return s_config;
}

const char *tud_descriptor_string_cb(uint8_t index, uint16_t langid)
{
	(void)langid;
	if (index >= sizeof s_str / sizeof s_str[0])
		return NULL;
	const char *s = s_str[index];
	if (s == NULL)
		return NULL;
	size_t n = strlen(s);
	if (n > 62) n = 62;                    /* max 31 UTF-16 codepoints */
	s_str_buf[0] = TUSB_DESC_STRING;       /* bDescriptorType */
	s_str_buf[1] = (uint16_t)(2 * n + 2);  /* bLength */
	for (size_t i = 0; i < n; i++)
		s_str_buf[2 + i] = (uint16_t)(uint8_t)s[i];
	return (const char *)s_str_buf;
}