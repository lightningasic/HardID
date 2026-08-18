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
#include "fido_u2f.h"
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
#include "lang.h"

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
/* True while the fido_task is blocked on a user-presence confirm dialog.
 * The main task stops polling the touch I2C bus while this is set: the
 * CST816D is read over a synchronous I2C port and concurrent polling from
 * two tasks makes the confirm dialog's ui_wait_press() miss presses. */
static volatile bool s_confirm_active;

/* Set by fido_usb_rx (TinyUSB task) when a CTAPHID packet arrives while NO
 * FIDO session is running (device sitting in the main menu). The menu loop
 * polls this and auto-enters the FIDO session so a browser WebAuthn call
 * started while the device is in the menu still reaches the confirm
 * screen. The pending packet(s) stay in the ring and are processed by the
 * freshly started fido_task, so the host's first INIT gets an answer. */
static volatile bool s_fido_wake;

/* Set once screen_run_fido has finished ALL session setup (LCD idle draw,
 * touch-injector pause, mutex). fido_task waits for this before pumping:
 * on an auto-wake entry the ring already holds a pending makeCredential,
 * so without the gate the confirm dialog would draw/touch the LCD and I2C
 * concurrently with the menu task's own setup — a startup race that
 * reboots the device. */
static volatile bool s_fido_ready;

bool fido_host_wake_pending(void)
{
	return s_fido_wake;
}

/* TinyUSB HID report ids: the descriptor in usb_desc.c has NO report id
 * (report = 64-byte CTAPHID packet exactly, matching the 64-byte endpoint
 * and CFG_TUD_HID_EP_BUFSIZE). tud_hid_report(0, ...) sends the raw
 * 64-byte report with no id prefix. */
enum { HID_REPORT_CTAPHID = 0 };

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
	if (!s_fido_run)
		s_fido_wake = true;   /* host talking while we sit in the menu */
	if (ring_next(s_rx.tail) == s_rx.head) {
		ESP_LOGW(TAG, "rx ring full, dropping HID packet");
		return;
	}
	/* The descriptor assigns NO report id: host sends the raw 64-byte
	 * CTAPHID packet directly. (A legacy path allowed a 1-byte report-id
	 * prefix; kept as a length-based guard in case a host still adds one.) */
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
	 * usbd_edpt_claim() fail and drops the frame. We therefore wait for the
	 * previous report to complete before submitting the next. The IN
	 * completion can occasionally take longer than the 1ms poll interval
	 * (full-speed SOF scheduling), so on a transient claim failure retry
	 * rather than dropping the frame: a lost continuation packet wedges the
	 * host in an infinite wait for the remainder of a multi-frame response. */
	for (int i = 0; i < nframes; i++) {
		bool sent = false;
		for (int attempt = 0; attempt < 10 && !sent; attempt++) {
			for (int w = 0; w < 100 && !tud_hid_ready(); w++)
				vTaskDelay(pdMS_TO_TICKS(1));
			sent = tud_hid_report(HID_REPORT_CTAPHID, frames[i],
			                      CTAPHID_PACKET_SIZE);
			if (!sent)
				vTaskDelay(pdMS_TO_TICKS(5));
		}
		if (!sent)
			ESP_LOGW(TAG, "hid report dropped (ep busy)");
	}
}

/* ---- FIDO task: pump RX ring through ctaphid_feed, emit staged TX ---- */

static void fido_task(void *arg)
{
	uint8_t inpkt[CTAPHID_PACKET_SIZE];
	uint8_t out[2][CTAPHID_PACKET_SIZE];

	/* wait for the session owner to finish LCD/touch setup before pumping;
	 * otherwise an auto-wake entry races the menu task on the LCD/I2C bus */
	while (!s_fido_ready && s_fido_run)
		vTaskDelay(pdMS_TO_TICKS(2));

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

/* CTAPHID_CANCEL (0x11): sent by the browser when the WebAuthn operation
 * is aborted. The core dispatcher is blocked inside this confirm dialog,
 * so the cancel packet would otherwise sit in the RX ring forever. We
 * poll the ring while waiting for touch and treat a pending cancel as a
 * user "No" (operation denied), which the browser surfaces as a cancelled
 * create()/get(). */
#define CTAPHID_CANCEL 0x11

static bool fido_cancel_pending(unsigned since)
{
	/* packet layout: cid(4) | cmd(1) | ... Only packets that arrived AFTER
	 * this confirm started count: a stale CANCEL from an aborted earlier
	 * ceremony (e.g. the browser cancelled while the device was rebooting)
	 * must not deny a fresh confirmation. */
	unsigned i = since;
	while (i != s_rx.tail) {
		if ((s_rx.data[i][4] & 0x7f) == CTAPHID_CANCEL) {
			/* drop the cancel and any stale packets before it */
			s_rx.head = i;
			return true;
		}
		i = ring_next(i);
	}
	return false;
}

static int fido_confirm_ui(const char *rp_name, bool is_register)
{
	/* F3: transport-only build keeps a plain Yes/No so RPs can exercise
	 * the wire end-to-end. Rich RP-domain render is milestone F5. */
	s_confirm_active = true;
	unsigned cancel_from = s_rx.head;   /* only fresh cancels count */
	lcd_fill(C_BG);
	lcd_text_wrap_utf8(2, 10, rp_name ? rp_name : os_lang_str(LKEY_UNKNOWN_RP), C_FG, C_BG);
	lcd_text_wrap_utf8(2, 60,
	                   is_register ? os_lang_str(LKEY_REGISTER_NEW_KEY)
	                               : os_lang_str(LKEY_CONFIRM_LOGIN),
	                   C_LBL, C_BG);
	lcd_rect_text_utf8(15, 200, 115, 250, os_lang_str(LKEY_NO), C_FG, C_BTN);
	lcd_rect_text_utf8(125, 200, 225, 250, os_lang_str(LKEY_YES), C_FG, C_OK);
	int rc = 0;
	for (;;) {
		if (fido_cancel_pending(cancel_from))
			break;                 /* host aborted -> deny */
		int px, py;
		if (!ui_touch_now(&px, &py)) {
			vTaskDelay(pdMS_TO_TICKS(8));
			continue;
		}
		/* stable press (3 consecutive reads), honouring cancel */
		int settle = 1;
		while (settle < 3) {
			if (fido_cancel_pending(cancel_from))
				goto done;
			vTaskDelay(pdMS_TO_TICKS(8));
			if (ui_touch_now(&px, &py))
				settle++;
			else
				settle = 0;
		}
		/* wait for release, tracking last coords, honouring cancel */
		int rx = px, ry = py, lost = 0;
		for (;;) {
			if (fido_cancel_pending(cancel_from))
				goto done;
			if (ui_touch_now(&rx, &ry))
				lost = 0;
			else if (++lost >= 3)
				break;
			vTaskDelay(pdMS_TO_TICKS(8));
		}
		if (ui_pt_in(px, py, 125, 200, 225, 250) &&
		    ui_pt_in(rx, ry, 125, 200, 225, 250)) { rc = 1; break; }
		if (ui_pt_in(px, py, 15, 200, 115, 250) &&
		    ui_pt_in(rx, ry, 15, 200, 115, 250)) { rc = 0; break; }
		ESP_LOGD(TAG, "confirm touch ignored: press=%d,%d release=%d,%d",
		         px, py, rx, ry);
	}
done:
	s_confirm_active = false;
	/* Give the user visible feedback on their tap (registration success,
	 * denial, or host-cancel) instead of leaving the Yes/No screen up as a
	 * stale artifact; then restore the FIDO serving idle screen. */
	lcd_fill(C_BG);
	if (rc == 1)
		lcd_text_wrap_utf8(2, 80,
		                   is_register ? os_lang_str(LKEY_REGISTRATION_OK)
		                               : os_lang_str(LKEY_LOGIN_OK),
		                   C_OK, C_BG);
	else
		lcd_text_wrap_utf8(2, 80, os_lang_str(LKEY_DENIED), C_DIM, C_BG);
	vTaskDelay(pdMS_TO_TICKS(700));
	lcd_fill(C_BG);
	lcd_utf8_str(2, 2, os_lang_str(LKEY_FIDO_SERVING), C_OK, C_BG, 1);
	lcd_utf8_str(2, 20, os_lang_str(LKEY_FIDO_PLUG_BROWSER), C_LBL, C_BG, 1);
	lcd_rect_text_utf8(60, 288, 180, 318, os_lang_str(LKEY_BACK), C_FG, C_BTN);
	ESP_LOGW(TAG, "confirm result rc=%d", rc);
	return rc;
}

/* ---- FIDO session entry (menu -> PIN gate -> serve CTAPHID) ---- */

void screen_run_fido(void)
{
	/* No PIN gate: PIN protects the wallet only (product decision). FIDO
	 * is a removable preinstalled app and its assertions are authorized by
	 * the per-request on-screen confirm (Yes), not the wallet PIN. */

	/* Wire the framer to the CTAP2 dispatcher exactly as host-verified. */
	ctaphid_init(&s_ctaphid);
	s_ctaphid.dispatch = ctap2_handle;
	s_ctaphid.msg_dispatch = fido_u2f_handle;   /* U2F probe answers (Chrome) */
	fido_set_confirm_handler(fido_confirm_ui);

	s_tx_lock = xSemaphoreCreateMutex();
	/* Auto-entered on host traffic: keep the pending packet(s) so the
	 * browser's in-flight INIT/getAssertion is answered. Manual menu entry
	 * starts clean (drops any stale ring bytes). */
	if (s_fido_wake) {
		s_fido_wake = false;
	} else {
		s_rx.head = s_rx.tail = 0;
	}
	s_fido_run = true;
	s_fido_exited = false;
	s_fido_ready = false;

	/* Draw the idle screen BEFORE spawning the transport task: on an
	 * auto-wake entry the ring already holds a pending getAssertion, so the
	 * task can open the confirm dialog within milliseconds — an idle draw
	 * after xTaskCreate would clobber the Yes/No screen while
	 * s_confirm_active simultaneously blocks the BACK poll (dead UI). */
	lcd_fill(C_BG);
	lcd_utf8_str(2, 2, os_lang_str(LKEY_FIDO_SERVING), C_OK, C_BG, 1);
	lcd_utf8_str(2, 20, os_lang_str(LKEY_FIDO_PLUG_BROWSER), C_LBL, C_BG, 1);
	lcd_rect_text_utf8(60, 288, 180, 318, os_lang_str(LKEY_BACK), C_FG, C_BTN);

	/* Own the CDC carrier for the duration of the FIDO session so the
	 * dev touch injector never steals HID-bound console bytes. Must happen
	 * BEFORE the transport task starts pumping (auto-wake entries can
	 * reach the confirm dialog within milliseconds). */
	touch_inject_set_busy(true);

	/* run the transport task for the duration of the session; it is stopped
	 * and torn down on exit so re-entering FIDO starts clean. The task
	 * waits for s_fido_ready before touching the ring/LCD/I2C. */
	BaseType_t ok = xTaskCreate(fido_task, "fido", 16384, NULL,
	                            tskIDLE_PRIORITY + 2, NULL);
	if (ok != pdPASS) {
		ESP_LOGE(TAG, "failed to create fido task");
		s_fido_run = false;
		touch_inject_set_busy(false);
		if (s_tx_lock) { vSemaphoreDelete(s_tx_lock); s_tx_lock = NULL; }
		lcd_text_wrap_utf8(2, 80, os_lang_str(LKEY_FIDO_TASK_ERR), C_ERR, C_BG);
		ui_wait_ack();
		return;
	}
	s_fido_ready = true;   /* all setup done: release the pump */

	/* Session loop: stay until BACK tapped (paused while the fido_task is
	 * showing a confirm dialog so the two tasks never contend for the
	 * touch I2C bus). */
	int px = 0, py = 0;
	for (;;) {
		vTaskDelay(pdMS_TO_TICKS(30));
		if (!s_confirm_active && ui_touch_now(&px, &py) &&
		    ui_pt_in(px, py, 60, 288, 180, 318))
			break;
	}
	/* Drain the BACK press so the tap that left the session does not also
	 * satisfy the following confirmation ack (which would exit in one tap
	 * whenever the finger is still down). */
	ui_wait_release(&px, &py);
	touch_inject_set_busy(false);
	/* Stop the transport task and release its resources before returning to
	 * the menu, so re-entering FIDO does not stack duplicate tasks/locks. */
	s_fido_run = false;
	while (!s_fido_exited)
		vTaskDelay(pdMS_TO_TICKS(5));
	if (s_tx_lock) { vSemaphoreDelete(s_tx_lock); s_tx_lock = NULL; }
	lcd_utf8_str(2, 40, os_lang_str(LKEY_SESSION_ENDED), C_DIM, C_BG, 1);
	ui_wait_ack();
}