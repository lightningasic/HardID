/*
 * HardID Hardware Wallet — CTAPHID over TinyUSB HID bridge (F3 transport)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Milestone F3 (host-verifiable slice already done in core/ + tests/):
 * this file is the on-board glue binding core/fido_ctaphid.c to the
 * TinyUSB HID interface described in usb_desc.c. It is intentionally thin:
 * every byte of CTAPHID framing / CTAP2 dispatch / fido_core / SE logic
 * lives in core and is exercised by tests/test_ctaphid_net.c on host.
 *
 *   S3 USB-OTG + TinyUSB HID 0xF1D0  ->  ctaphid_feed()  ->  ctap2_handle()
 *                                     <-  staged frames <-  fido_core + SE
 *
 * The FIDO menu entry (screen_run_fido) first applies the device PIN gate
 * (decision A6), then serves CTAPHID frames over the HID interface.
 * The per-request touch confirm screen (design §6) is milestone F5 — this
 * file wires the core confirm hook to the existing UI but the rich render
 * is deferred; the default core handler denies (safe default, A3).
 *
 * BUILD NOTE (environment): needs the espressif esp_tinyusb managed
 * component + real S3 hardware. Not buildable/verifiable on this box
 * (no network to fetch esp_tinyusb, no USB hardware). Transport layer is
 * fully host-verified in core/ (tests/test_ctaphid_net.c, 26 checks).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "tusb.h"
#include "device/usbd.h"
#include "class/hid/hid_device.h"

#include "ctap2.h"
#include "fido_ctaphid.h"
#include "fido_core.h"
#include "fido.h"
#include "se_driver.h"
#include "secure_zero.h"

#include "display.h"
#include "devcfg.h"
#include "pin.h"
#include "inter.h"
#include "keypad.h"
#include "screen.h"
#include "touch.h"
#include "usb_desc.h"

static const char *TAG = "fido_esp";

/* One CTAPHID channel, wired to the CTAP2 dispatcher (identical to the
 * host-verified configuration in tests/test_ctaphid_net.c). */
static ctaphid_t s_ctaphid;
static SemaphoreHandle_t s_tx_lock;

/* Session lifecycle: fido_task loops while s_fido_run is set, then sets
 * s_fido_exited before deleting itself so screen_run_fido can tear the
 * session down safely (no task/semaphore leak on menu re-entry). */
static volatile bool s_fido_run;
static volatile bool s_fido_exited;

/* TinyUSB HID report ids: matching the descriptor in usb_desc.c (id 1 =
 * CTAPHID 64-byte report). */
enum { HID_REPORT_CTAPHID = 1 };

/* FIFO of HID reports (64B each) received from the host, drained by the
 * FIDO task. CTAPHID is sequential single-channel in v1, so a small
 * ring is enough to ride-out the USB interrupt burst. */
#define RX_RING_N   8
typedef struct {
	uint8_t  data[RX_RING_N][CTAPHID_PACKET_SIZE];
	volatile unsigned head, tail;
} tx_ring_t;

static tx_ring_t s_rx;

static inline unsigned ring_next(unsigned i) { return (i + 1) % RX_RING_N; }

/* ---- USB RX: HID OUT report from the host into the ring ---- */

static void fido_usb_rx(const uint8_t *report, uint16_t len)
{
	if (ring_next(s_rx.tail) == s_rx.head) {
		ESP_LOGW(TAG, "rx ring full, dropping HID packet");
		return;
	}
	/* The composite descriptor assigns report ID 1 to the CTAPHID report,
	 * so the host prefixes every OUT report with the 1-byte ID (65-byte
	 * report). Step over it to reach the 64-byte CTAPHID packet. Detect by
	 * LENGTH, not content: a packet's first CID byte may itself be 0x01. */
	if (len == CTAPHID_PACKET_SIZE + 1) {
		report++;
		len--;
	}
	uint16_t n = len;
	if (n > CTAPHID_PACKET_SIZE)
		n = CTAPHID_PACKET_SIZE;
	memcpy(s_rx.data[s_rx.tail], report, n);
	if (n < CTAPHID_PACKET_SIZE)
		memset(s_rx.data[s_rx.tail] + n, 0,
		       CTAPHID_PACKET_SIZE - n);
	s_rx.tail = ring_next(s_rx.tail);
}

/* TinyUSB HID class driver: called when an OUT report arrives. */
void tud_hid_set_report_cb(uint8_t itf, uint8_t report_id,
                           hid_report_type_t rtype,
                           uint8_t const *buffer, uint16_t bufsize)
{
	(void)itf; (void)report_id; (void)rtype;
	fido_usb_rx(buffer, bufsize);
}

/* TinyUSB HID class driver: return the CTAP-HID report descriptor. */
uint8_t const *tud_hid_descriptor_report_cb(uint8_t itf)
{
	(void)itf;
	return hardid_usb_hid_report_desc();
}

/* TinyUSB HID class driver: GET_REPORT. CTAPHID never polls reports via
 * control GET_REPORT (host pushes OUT reports instead); return 0 so the
 * request stalls cleanly. */
uint16_t tud_hid_get_report_cb(uint8_t itf, uint8_t report_id,
                               hid_report_type_t rtype,
                               uint8_t *buf, uint16_t reqlen)
{
	(void)itf; (void)report_id; (void)rtype; (void)buf; (void)reqlen;
	return 0;
}

/* ---- USB TX: drain staged CTAPHID frames out as HID IN reports ---- */

static void fido_usb_tx_drain(uint8_t (*frames)[CTAPHID_PACKET_SIZE], int nframes)
{
	/* tud_hid_report() claims the single IN endpoint buffer and starts the
	 * transfer; it is NOT a fifo. Sending back-to-back while busy makes
	 * usbd_edpt_claim() fail and silently drops the frame, so wait for the
	 * previous report to complete before submitting the next. */
	for (int i = 0; i < nframes; i++) {
		for (int w = 0; w < 100 && !tud_hid_ready(); w++)
			vTaskDelay(pdMS_TO_TICKS(1));
		if (!tud_hid_report(HID_REPORT_CTAPHID, frames[i], CTAPHID_PACKET_SIZE))
			ESP_LOGW(TAG, "hid report dropped (ep busy)");
	}
}

/* ---- FIDO task: pump RX ring through ctaphid_feed, emit staged TX ---- */

static void fido_task(void *arg)
{
	uint8_t inpkt[CTAPHID_PACKET_SIZE];
	uint8_t out[2][CTAPHID_PACKET_SIZE];

	while (s_fido_run) {
		/* process each queued host packet, then drain staged responses */
		unsigned cur;
		while (s_rx.head != s_rx.tail) {
			cur = s_rx.head;
			/* read the slot BEFORE advancing head: advancing first would
			 * let the producer (TinyUSB task) treat this slot as free and
			 * overwrite it mid-copy (torn 64-byte packet). */
			memcpy(inpkt, s_rx.data[cur], CTAPHID_PACKET_SIZE);
			s_rx.head = ring_next(s_rx.head);

			int n = 0;
			xSemaphoreTake(s_tx_lock, portMAX_DELAY);
			n = ctaphid_feed(&s_ctaphid, inpkt, out, 2);
			xSemaphoreGive(s_tx_lock);
			if (n > 0)
				fido_usb_tx_drain(out, n);
		}
		/* drain any response staged without a new input (single packet
		 * responses triggered by the last CONT already emitted above) */
		int n;
		do {
			xSemaphoreTake(s_tx_lock, portMAX_DELAY);
			n = ctaphid_feed(&s_ctaphid, NULL, out, 2);
			xSemaphoreGive(s_tx_lock);
			if (n > 0)
				fido_usb_tx_drain(out, n);
		} while (n > 0 && s_fido_run);

		vTaskDelay(pdMS_TO_TICKS(2));
	}
	s_fido_exited = true;
	vTaskDelete(NULL);
}

/* ---- User-presence hook: wired to the UI confirm (F5 expands the
 *      rendering). Core default (NULL) DENIES, safe default (A3). ---- */

static int fido_confirm_ui(const char *rp_name, bool is_register)
{
	/* F3: transport-only build keeps a plain Yes/No so RPs can exercise
	 * the wire end-to-end. Rich RP-domain render is milestone F5. */
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, rp_name ? rp_name : "(unknown RP)", C_FG, C_BG);
	lcd_text_wrap(2, 60,
	              is_register ? "Register new login key?" : "Confirm login?",
	              C_LBL, C_BG);
	return ui_confirm_yesno();
}

/* ---- FIDO session entry (menu -> PIN gate -> serve CTAPHID) ---- */

void screen_run_fido(void)
{
	const se_driver_t *se = se_active();

	/* A6: device PIN gate before serving any FIDO I/O (same as link). */
	if (os_dev_no_pin_enabled()) {
		if (se->dev_unlock)
			se->dev_unlock();
	} else {
		char pin[OS_PIN_MAX_LEN + 1];
		int n = ui_enter_pin(pin, sizeof(pin));
		if (n < 0) { lcd_text_wrap(2, 80, "cancelled", C_ERR, C_BG); return; }
		uint32_t wait; bool duress;
		int vr = se->verify_pin((const uint8_t *)pin, (size_t)n, &wait, &duress);
		os_secure_bzero(pin, sizeof(pin));
		if (vr != SE_OK) {
			lcd_fill(C_BG);
			lcd_text_wrap(2, 10, "wrong PIN", C_ERR, C_BG);
			ui_wait_ack();
			return;
		}
	}

	/* Wire the framer to the CTAP2 dispatcher exactly as host-verified. */
	ctaphid_init(&s_ctaphid);
	s_ctaphid.dispatch = ctap2_handle;
	fido_set_confirm_handler(fido_confirm_ui);

	s_tx_lock = xSemaphoreCreateMutex();
	s_rx.head = s_rx.tail = 0;
	s_fido_run = true;
	s_fido_exited = false;

	/* run the transport task for the duration of the session; it is stopped
	 * and torn down on exit so re-entering FIDO starts clean. */
	BaseType_t ok = xTaskCreate(fido_task, "fido", 4096, NULL,
	                            tskIDLE_PRIORITY + 2, NULL);
	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create fido task");
		s_fido_run = false;
		if (s_tx_lock) { vSemaphoreDelete(s_tx_lock); s_tx_lock = NULL; }
		lcd_text_wrap(2, 80, "FIDO task error", C_ERR, C_BG);
		ui_wait_ack();
		return;
	}

	lcd_fill(C_BG);
	lcd_line(2, 2, "FIDO serving", C_OK, C_BG);
	lcd_line(2, 14, "plug into a browser", C_LBL, C_BG);
	lcd_rect_text(60, 288, 180, 318, "BACK", C_FG, C_BTN);

	/* Own the CDC carrier for the duration of the FIDO session so the
	 * dev touch injector never steals HID-bound console bytes. */
	touch_inject_set_busy(true);

	/* Session loop: stay until BACK tapped. */
	int px = 0, py = 0;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(30));
		if (ui_touch_now(&px, &py) && ui_pt_in(px, py, 60, 288, 180, 318))
			break;
	}
	touch_inject_set_busy(false);
	/* Stop the transport task and release its resources before returning to
	 * the menu, so re-entering FIDO does not stack duplicate tasks/locks. */
	s_fido_run = false;
	while (!s_fido_exited)
		vTaskDelay(pdMS_TO_TICKS(5));
	if (s_tx_lock) { vSemaphoreDelete(s_tx_lock); s_tx_lock = NULL; }
	lcd_line(2, 40, "session ended", C_DIM, C_BG);
	ui_wait_ack();
}