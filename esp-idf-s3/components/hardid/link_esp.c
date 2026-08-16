/*
 * HardID - host-link session screen over the TinyUSB CDC carrier
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * One device screen that opens a short host session over the composite
 * CDC-ACM interface exposed by esp_tinyusb (usb_esp.c / usb_desc.c). A
 * framed protocol (core/linkproto) carries a host SIGN request — app id,
 * BIP32 path, and the raw transaction bytes (PSBT / EVM tx). The request is
 * routed through the SAME sign service as the on-device SIGN menu
 * (os_signsvc_delegate): the device parses the tx, renders the intent on
 * screen and requires an explicit confirm, then signs the real chain
 * sighash (WYSIWYS). This is the transport foundation for the manual's
 * "verify before sign" goal (P1).
 *
 * Since F3 (design §1.1) the USB-Serial-JTAG port is released to the
 * USB-OTG TinyUSB composite; the linkproto byte stream moved to the
 * composite CDC. The protocol and service layers stay host-tested in
 * tests/test_linkproto.c and tests/test_linksvc.c.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "usb_desc.h"

#include "display.h"
#include "devcfg.h"
#include "pin.h"
#include "se_driver.h"
#include "secure_zero.h"
#include "linkproto.h"
#include "linksvc.h"
#include "inter.h"
#include "keypad.h"
#include "screen.h"
#include "touch.h"
#include "lang.h"

void screen_run_link_host(void)
{
	const se_driver_t *se = se_active();

	/* DEV-ONLY: no-PIN builds skip the unlock prompt (mock auto-unlocks). */
	if (os_dev_no_pin_enabled()) {
		if (se->dev_unlock)
			se->dev_unlock();
	} else {
		/* require a successful PIN unlock before serving any request */
		char pin[OS_PIN_MAX_LEN + 1];
		int n = ui_enter_pin(pin, sizeof(pin));
		if (n < 0) { lcd_text_wrap_utf8(2, 80, os_lang_str(LKEY_CANCELLED), C_ERR, C_BG); return; }
		uint32_t wait; bool duress;
		int vr = se->verify_pin((const uint8_t *)pin, (size_t)n, &wait, &duress);
		os_secure_bzero(pin, sizeof(pin));
		if (vr != SE_OK) {
			lcd_fill(C_BG);
			lcd_text_wrap_utf8(2, 10, os_lang_str(LKEY_WRONG_PIN), C_ERR, C_BG);
			ui_wait_ack();
			return;
		}
	}

	lcd_fill(C_BG);
	lcd_utf8_str(2, 2, os_lang_str(LKEY_HOST_LINK_SERVING), C_OK, C_BG, 1);
	lcd_utf8_str(2, 14, os_lang_str(LKEY_WAITING_FRAMES), C_LBL, C_BG, 1);
	/* explicit BACK button to leave the session — the hint line no
	 * longer hangs forever and stray taps do not cancel it */
	lcd_rect_text_utf8(60, 288, 180, 318, os_lang_str(LKEY_BACK), C_FG, C_BTN);

	/* Own the CDC carrier: pause the dev touch injector so it cannot
	 * steal linkproto bytes, and release it when the session ends. */
	touch_inject_set_busy(true);

	/* byte-accreting frame reassembly. A full SIGN request can carry a
	 * multi-KB tx, so keep the reassembly buffers out of the 8KB ui_task
	 * stack. Single link session at a time, static is safe. */
	static uint8_t rxbuf[HD_LINK_MAX_FRAME];
	static uint8_t reply[HD_LINK_MAX_FRAME];
	int rxlen = 0;
	int px = 0, py = 0;
	for (;;) {
		uint8_t b;
		int got = hardid_usb_read_byte(&b, pdMS_TO_TICKS(30));
		if (got == 1) {
			if (rxlen < (int)sizeof(rxbuf))
				rxbuf[rxlen++] = b;
			uint8_t type; uint16_t seq; const uint8_t *pl; size_t plen;
			if (rxlen >= HD_LINK_HDR_LEN &&
			    hd_link_parse(rxbuf, (size_t)rxlen, &type, &seq, &pl, &plen) == 0) {
				int rn = hd_link_serve(screen_confirm_intent, type, seq,
				                       pl, plen, reply, sizeof reply);
				if (rn > 0)
					hardid_usb_write(reply, (size_t)rn,
					                 pdMS_TO_TICKS(100));
				rxlen = 0;
				/* return to the session screen: the confirm hook drew its
				 * own full-screen intent + Yes/No, so restore the waiting
				 * view (never leave a stale confirm up) */
				lcd_fill(C_BG);
				lcd_utf8_str(2, 2, os_lang_str(LKEY_HOST_LINK_SERVING), C_OK, C_BG, 1);
				lcd_utf8_str(2, 14, os_lang_str(LKEY_WAITING_FRAMES), C_LBL, C_BG, 1);
				lcd_rect_text_utf8(60, 288, 180, 318, os_lang_str(LKEY_BACK), C_FG, C_BTN);
			} else if (rxlen >= (int)sizeof(rxbuf)) {
				rxlen = 0;   /* overrun/dropped sync: reset */
			}
		} else if (ui_touch_now(&px, &py)) {
			/* touching BACK cancels the session; anything else is ignored */
			if (ui_pt_in(px, py, 60, 288, 180, 318))
				break;
		}
	}
	touch_inject_set_busy(false);
	lcd_utf8_str(2, 40, os_lang_str(LKEY_SESSION_ENDED), C_DIM, C_BG, 1);
	ui_wait_ack();
	return;
}
