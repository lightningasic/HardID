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
 * esp_tinyusb 2.x provides tud_descriptor_*_cb() itself (descriptors_control.c,
 * bound through tinyusb_desc_config_t passed to tinyusb_driver_install()).
 * This file therefore only EXPOSES the descriptor data; it must not define
 * those callbacks or the link fails with duplicate symbols.
 *
 * Descriptors are hand-laid raw bytes (the same style as the TinyUSB
 * samples) so the layout is unambiguous and self-auditable here.
 */

#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include "tinyusb.h"
#include "tusb.h"

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

/* ---- String descriptors ----
 * esp_tinyusb 2.x expects a plain UTF-8 array; index 0 must be the 2-byte
 * language id (US English, 0x0409 LE) and entries 1.. map to the
 * iManufacturer / iProduct / iSerialNumber indexes of the device
 * descriptor. descriptors_control.c converts them to UTF-16LE on the fly.
 */
static const char *const s_str[] = {
	"\x09\x04",            /* [0] LANGID: US English */
	"LightningASIC",       /* [1] iManufacturer */
	"HardID Secure Wallet",/* [2] iProduct */
	"000000000001",        /* [3] iSerialNumber */
};

/* ---- Exposed descriptor data (bound by usb_esp.c -> tinyusb_driver_install) ---- */

const tusb_desc_device_t *hardid_usb_device_desc(void)
{
	return &s_dev;
}

const uint8_t *hardid_usb_fs_config_desc(void)
{
	return s_config;
}

/* HID report descriptor lives inside the config blob (offset 93, 31 bytes). */
const uint8_t *hardid_usb_hid_report_desc(void)
{
	return s_config + 93;
}

const char **hardid_usb_strings(int *count)
{
	if (count)
		*count = (int)(sizeof s_str / sizeof s_str[0]);
	return (const char **)s_str;
}
