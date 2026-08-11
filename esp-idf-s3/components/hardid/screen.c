/*
 * HardID — device screen flows (initialize / sign / factory reset)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>

#include "esp_random.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_app_desc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "display.h"
#include "boot.h"
#include "devcfg.h"
#include "pin.h"
#include "rng.h"
#include "se_driver.h"
#include "seed.h"
#include "bip39.h"
#include "secure_zero.h"
#include "inter.h"
#include "keypad.h"
#include "app.h"
#include "app_catalog.h"
#include "signsvc.h"
#include "screen.h"
#include "logo.h"
#include "font7.h"

void screen_run_splash(void)
{
	/* Boot logo bitmap centered, HardID wordmark below it. */
	lcd_fill(C_BG);
	int x = (LCD_H_RES - LOGO_W) / 2;
	lcd_bitmap(x, 60, LOGO_W, LOGO_H, logo_rgb565);

/* "HardID" wordmark, 2x scale, centered under the mark. */
	lcd_line_scaled((LCD_H_RES - 6 * (FONT_CHAR_W + 1) * 2) / 2,
	                60 + LOGO_H + 18, "HardID", C_LBL, C_BG, 2);

	/* Hold the splash for 2 s before handing over to the menu. */
	vTaskDelay(pdMS_TO_TICKS(2000));
}

void screen_run_sign(void)
{
	const se_driver_t *se = se_active();

	bool initd;
	se->is_initialized(&initd);
	if (!initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Not initialized. Run Initialize first.", C_WARN, C_BG);
		return;
	}

	/* V2.0: signing is app-mediated. If only one usable app exists (core
	 * build), use it directly; otherwise send the user through the app
	 * market selection. */
	size_t usable = 0;
	const os_app *pick = NULL;
	for (size_t i = 0; i < os_app_count(); i++) {
		const os_app *a = os_app_at(i);
		if (!a || a->state == OS_APP_SUSPENDED)
			continue;
		usable++;
		pick = a;
	}
	if (usable == 1) {
		screen_run_sign_for_app(pick);
		return;
	}
	if (usable == 0) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "No app available.", C_WARN, C_BG);
		return;
	}
	screen_run_apps();
}

/* Render a parsed intent and ask the user to confirm. This is the UI
 * confirmation hook passed to os_signsvc_delegate: the SAME struct that is
 * rendered here is the one the signer consumes — WYSIWYS by construction.
 * UNKNOWN intents force a double tap-to-confirm (escalated) so a risky
 * call can never be confirmed with a casual single tap. */
bool screen_confirm_intent(const os_tx_intent *it)
{
	lcd_fill(C_BG);
	lcd_line(2, 2, "CONFIRM", C_LBL, C_BG);
	char line[48];

	if (it->kind == OS_INTENT_UNKNOWN) {
		lcd_text_wrap(2, 18, "UNKNOWN CALL", C_ERR, C_BG);
		lcd_text_wrap(2, 34, "Not parseable. Confirm twice to sign.", C_WARN, C_BG);
		if (!ui_confirm_yesno())
			return false;
		return ui_confirm_yesno();
	}

	const char *kind = "transfer";
	switch (it->kind) {
	case OS_INTENT_TRANSFER:       kind = "transfer";  break;
	case OS_INTENT_ERC20_TRANSFER: kind = "token transfer"; break;
	case OS_INTENT_ERC20_APPROVE:  kind = "approve";   break;
	case OS_INTENT_CONTRACT_CALL:  kind = "contract";  break;
	default:                       kind = "transfer";  break;
	}
	snprintf(line, sizeof line, "%s %s", it->symbol, kind);
	lcd_line(2, 16, line, C_FG, C_BG);

	snprintf(line, sizeof line, "to %.42s", it->to);
	lcd_line(2, 30, line, C_FG, C_BG);

	if (it->amount_token[0]) {
		/* ERC20 kinds carry raw token units — never glue the NATIVE
		 * symbol onto them ("1000 ETH" for a USDC transfer is a lie).
		 * Native/BTC amounts are already decimal coin strings. */
		if (it->kind == OS_INTENT_ERC20_TRANSFER ||
		    it->kind == OS_INTENT_ERC20_APPROVE)
			snprintf(line, sizeof line, "amount %.24s units",
			         it->amount_token);
		else
			snprintf(line, sizeof line, "amount %.24s %.10s",
			         it->amount_token, it->symbol);
	} else {
		snprintf(line, sizeof line, "amount %llu %.10s",
		         (unsigned long long)it->amount, it->symbol);
	}
	lcd_line(2, 44, line, C_FG, C_BG);

	if (it->method[0]) {
		snprintf(line, sizeof line, "method %s", it->method);
		lcd_line(2, 58, line, C_FG, C_BG);
	}
	{
		/* fee in decimal coin units (sats for BTC chains, wei for EVM) */
		char fee[24];
		os_fmt_coin_amount(fee, sizeof fee, it->fee_limit,
		                   it->chain == OS_CHAIN_BTC ? 8 : 18);
		snprintf(line, sizeof line, "max fee %s %.10s", fee, it->symbol);
	}
	lcd_line(2, 72, line, C_FG, C_BG);
	if (it->chain_id) {
		snprintf(line, sizeof line, "chain id %llu",
		         (unsigned long long)it->chain_id);
		lcd_line(2, 86, line, C_FG, C_BG);
	}

	/* Explicit Yes/No — a signature is NEVER granted by a stray tap on a
	 * label that reads "tap to CONFIRM" while the only tappable control is
	 * BACK. Confirm returns false unless the user presses Yes. */
	lcd_line(2, 100, "sign?", C_LBL, C_BG);
	return ui_confirm_yesno();
}

void screen_run_sign_for_app(const os_app *app)
{
	const se_driver_t *se = se_active();

	bool initd;
	se->is_initialized(&initd);
	if (!initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Not initialized. Run Initialize first.", C_WARN, C_BG);
		return;
	}

	lcd_fill(C_BG);
	lcd_line(2, 2, "Unlock to sign", C_LBL, C_BG);

	/* DEV-ONLY: no-PIN builds skip the unlock prompt entirely. */
	if (os_dev_no_pin_enabled()) {
		if (se->dev_unlock)
			se->dev_unlock();
	} else {
		char pin[OS_PIN_MAX_LEN + 1];
		int n = ui_enter_pin(pin, sizeof(pin));
		if (n < 0) { lcd_text_wrap(2, 16, "cancelled", C_ERR, C_BG); return; }

		uint32_t wait;
		bool duress;
		int vr = se->verify_pin((const uint8_t *)pin, n, &wait, &duress);
		os_secure_bzero(pin, sizeof(pin));
		if (vr != SE_OK) {
			lcd_fill(C_BG);
			lcd_text_wrap(2, 10, "wrong PIN", C_ERR, C_BG);
			return;
		}
	}

	/* V2.0: delegate signing through signsvc with the on-screen confirm
	 * hook. A sample tx is synthesized on-device for the bring-up build;
	 * the real tx arrives via HOST LINK / App market install flow. */
	uint8_t tx[256];
	uint32_t path[3] = { 0x80000000u | 44,
	                    0x80000000u | app->coin_type,
	                    0x80000000u | 0 };       /* m/44'/coin'/0' (hardened) */
	size_t tx_len = 0;

	if (os_evm_chain_id_for_coin(app->coin_type) != 0) {
		/* minimal legacy EVM transfer via shared core builder so the
		 * on-device demo can never drift from the test harness. Works
		 * for every EVM-family app (ETH/ETC/POLYGON): signsvc injects
		 * the app's own chainId into the EIP-155 sighash. */
		uint8_t to[20];
		memset(to, 0x11, sizeof to);
		tx_len = os_clearsign_build_demo_legacy(tx, 20, 21000, to, 1000);
	} else {
		/* BTC: no built-in demo tx — ask host for a PSBT later. */
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "BTC demo: use HOST LINK to load a PSBT.",
		              C_WARN, C_BG);
		ui_wait_ack();
		return;
	}

	os_sign_outcome oc =
		os_signsvc_delegate(app->app_id, tx, tx_len, path, 3,
		                    screen_confirm_intent);

	lcd_fill(C_BG);
	switch (oc.result) {
	case OS_SIGN_OK: {
		if (os_evm_chain_id_for_coin(app->coin_type) != 0) {
			lcd_line(2, 2, "Signature (r||s)", C_LBL, C_BG);
		} else {
			char ln[40];
			snprintf(ln, sizeof ln, "Signed %u input(s), sig[0]:",
			         (unsigned)oc.sig_count);
			lcd_line(2, 2, ln, C_LBL, C_BG);
		}
		char hex[130];
		for (int i = 0; i < 64; i++)
			snprintf(hex + i * 2, 3, "%02x", oc.sig64[i]);
		lcd_text_wrap(2, 16, hex, C_FG, C_BG);
		ui_wait_ack();
		break;
	}
	case OS_SIGN_REJECTED:
		lcd_text_wrap(2, 10, "Rejected by user.", C_WARN, C_BG);
		ui_wait_ack();
		break;
	case OS_SIGN_LOCKED:
		lcd_text_wrap(2, 10, "Session locked. Re-enter PIN.", C_ERR, C_BG);
		ui_wait_ack();
		break;
	default:
		lcd_text_wrap(2, 10, "Sign unavailable (rc=%d).", C_ERR, C_BG);
		ui_wait_ack();
		break;
	}
}

void screen_run_factory_reset(void)
{
	/* Strict two-step confirmation. First type the word RESET on the
	 * on-screen keypad — the same physical effort a malicious bystander
	 * could not casually complete. Then prove ownership by entering the
	 * device PIN — or, if no PIN was ever set, SET one: a device must never
	 * be wiped while it is PIN-less. Only then is the SE wiped. */
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, "Type RESET to confirm wipe.", C_WARN, C_BG);
	char word[16];
	if (kp_capture("TYPE RESET", word, (int)sizeof(word), 0, 0) != 0) {
		lcd_text_wrap(2, 100, "cancelled", C_FG, C_BG);
		return;
	}
	bool ok = (strcmp(word, "RESET") == 0);
	os_secure_bzero(word, sizeof(word));
	if (!ok) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Not confirmed. Wipe aborted.", C_ERR, C_BG);
		return;
	}

	const se_driver_t *se = se_active();
	bool initd;
	se->is_initialized(&initd);

	/* DEV-ONLY: no-PIN builds skip the ownership PIN gate (the typed
	 * "RESET" word above is still required). */
	if (!os_dev_no_pin_enabled() && initd) {
		/* a PIN exists: entering the correct one proves ownership */
		lcd_fill(C_BG);
		char pin[OS_PIN_MAX_LEN + 1];
		int pin_len = ui_enter_pin(pin, sizeof(pin));
		if (pin_len < 0) {
			lcd_text_wrap(2, 100, "cancelled", C_FG, C_BG);
			return;
		}
		uint32_t wait;
		bool duress;
		int vr = se->verify_pin((const uint8_t *)pin, (size_t)pin_len,
		                        &wait, &duress);
		os_secure_bzero(pin, sizeof(pin));
		if (vr != SE_OK) {
			lcd_fill(C_BG);
			lcd_text_wrap(2, 10, "Wrong PIN. Wipe aborted.", C_ERR, C_BG);
			return;
		}
	} else if (!os_dev_no_pin_enabled()) {
		/* no PIN ever set: force one before allowing a wipe so the
		 * device cannot be wiped while unprotected */
		lcd_fill(C_BG);
		char pin[OS_PIN_MAX_LEN + 1];
		int pin_len = ui_set_pin(pin, sizeof(pin));
		if (pin_len < 0) {
			lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
			return;
		}
		se->set_pin((const uint8_t *)pin, (size_t)pin_len);
		os_secure_bzero(pin, sizeof(pin));
	}

	se->wipe();
	os_board_display_home();
	lcd_text_wrap(2, 60, "Device wiped. Re-initialize to set a seed.", C_OK, C_BG);
}

/* Display the recovery phrase one word per screen, big and centered, with
 * a Back (left) key to revisit the previous word (aborts on the first
 * word) and a Next key to advance. Returns 0 when the user has confirmed
 * through every word, -1 if aborted from the first word. */
static int screen_show_words(const char *mnemonic)
{
	const char *words[32];
	int total = 0;
	const char *p = mnemonic;
	while (*p) {
		while (*p == ' ') p++;
		if (!*p) break;
		words[total++] = p;
		while (*p && *p != ' ') p++;
	}
	int idx = 0;
	while (idx < total) {
		const char *start = words[idx];
		const char *end = start;
		while (*end && *end != ' ') end++;
		int wlen = (int)(end - start);
		lcd_fill(C_BG);
		char title[24];
		snprintf(title, sizeof title, "Word %d/%d", idx + 1, total);
		lcd_line(2, 8, title, C_LBL, C_BG);

		/* the embedded 8x16 font is A-Z only: uppercase the word */
		char word[16];
		int n = wlen < 15 ? wlen : 15;
		for (int i = 0; i < n; i++) {
			char c = start[i];
			word[i] = (c >= 'a' && c <= 'z') ? (char)(c - 'a' + 'A') : c;
		}
		word[n] = '\0';

		int scale = 3;
		int adv = F8_W * scale + 2;
		int tw = (int)strlen(word) * adv - 2;
		if (tw > 220) {
			scale = 2;
			adv = F8_W * scale + 2;
			tw = (int)strlen(word) * adv - 2;
		}
		int x = (240 - tw) / 2;
		if (x < 0) x = 0;
		for (int i = 0; word[i]; i++)
			lcd_gl8x16(x + i * adv, 120, word[i], C_FG, C_BG, scale);

		lcd_rect_text(15, 240, 115, 290, "Back", C_FG, C_BTN);
		lcd_rect_text(125, 240, 225, 290, "Next", C_FG, C_BTN);
		for (;;) {
			int px, py;
			ui_wait_press(&px, &py);
			int rx = px, ry = py;
			ui_wait_release(&rx, &ry);
			if (ui_pt_in(px, py, 15, 240, 115, 290) &&
			    ui_pt_in(rx, ry, 15, 240, 115, 290)) {
				if (idx == 0)
					return -1;      /* aborted back to the menu */
				idx--;
				break;
			}
			if (ui_pt_in(px, py, 125, 240, 225, 290) &&
			    ui_pt_in(rx, ry, 125, 240, 225, 290)) {
				idx++;
				break;
			}
		}
	}
	return 0;
}

/* Prompt for an optional BIP39 passphrase and confirm it by typing it
 * twice (any typo would otherwise yield a permanently different key). On
 * mismatch the user is told and asked to enter it again from scratch.
 * Returns:
 *   1  passphrase set and confirmed (out holds it)
 *   0  user skipped (out empty)
 *  -1  capture aborted (out unchanged)
 */
static int prompt_passphrase(char *out, size_t out_max)
{
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, "Enable brain phrase?", C_WARN, C_BG);
	if (!ui_confirm_yesno())
		return 0;

	for (;;) {
		lcd_fill(C_BG);
		if (kp_capture_alpha("BRAIN PHRASE", out, (int)out_max) != 0)
			return -1;
		if (out[0] == '\0')
			return 0;   /* typed nothing -> no passphrase */

		char again[OS_BIP39_MNEMONIC_MAX];
		again[0] = '\0';
		lcd_fill(C_BG);
		if (kp_capture_alpha("CONFIRM BRAIN PHRASE", again,
		                     (int)sizeof(again)) != 0) {
			os_secure_bzero(again, sizeof(again));
			return -1;
		}
		bool match = strcmp(again, out) == 0;
		os_secure_bzero(again, sizeof(again));
		if (match)
			return 1;
		/* typo somewhere: tell the user and re-enter from the top */
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Passphrase mismatch!", C_ERR, C_BG);
		lcd_text_wrap(2, 30, "Enter it again.", C_FG, C_BG);
		ui_wait_ack();
	}
}

/* Boot-time passphrase gate (TREZOR model). Every power-on on an
 * initialized device asks whether the user wants a passphrase; if yes it
 * is captured + confirmed and folded into a volatile session seed via
 * se->derive_session(). The passphrase itself is never stored — it only
 * exists in the operator's memory, so this gate runs on every boot. A
 * wiped/blank device has nothing to protect yet and skips straight past. */
void screen_boot_passphrase_gate(void)
{
	const se_driver_t *se = se_active();
	if (!se || !se->is_initialized)
		return;

	bool initd = false;
	if (se->is_initialized(&initd) != SE_OK) {
		/* Cannot determine state: fail LOUD, not open. Silently skipping
		 * would run the device on the base seed while the user believes a
		 * passphrase session is armed. */
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "SE status error — passphrase gate failed",
		              C_ERR, C_BG);
		ui_wait_ack();
		return;
	}
	if (!initd)
		return;
	if (!se->derive_session) {
		/* An initialized device whose backend cannot arm a passphrase
		 * session must say so — never run on the base seed in silence. */
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Backend lacks passphrase support",
		              C_ERR, C_BG);
		ui_wait_ack();
		return;
	}

	char pass[OS_BIP39_MNEMONIC_MAX];
	int prc = prompt_passphrase(pass, sizeof(pass));
	if (prc == 1 && pass[0] != '\0')
		se->derive_session((const uint8_t *)pass, strlen(pass));
	else
		se->derive_session(NULL, 0);   /* back to the plain base seed */
	os_secure_bzero(pass, sizeof(pass));
}

void screen_run_initialize(void)
{
	const se_driver_t *se = se_active();
	bool initd;
	se->is_initialized(&initd);
	if (initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Device already initialized. Wipe to re-seed.", C_WARN, C_BG);
		return;
	}

	uint8_t seed32[OS_SEED_LEN], seed64[OS_BIP39_SEED_LEN], host[32];
	char mnemonic[OS_BIP39_MNEMONIC_MAX];

	/* 0. Word-count choice: 12 words (128-bit entropy) or 24 words
	 * (256-bit). Both are secure; 24 is the larger safety margin. The
	 * entropy always comes from the SE+MCU+host HKDF — the choice only
	 * selects how many bytes of it feed BIP39. */
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, "Phrase length?", C_LBL, C_BG);
	lcd_text_wrap(2, 30, "12 words = 128-bit", C_FG, C_BG);
	lcd_text_wrap(2, 46, "24 words = 256-bit", C_FG, C_BG);
	lcd_rect_text(15, 250, 115, 300, "12", C_FG, C_BTN);
	lcd_rect_text(125, 250, 225, 300, "24", C_FG, C_BTN);
	const bool test_seed = os_dev_test_seed_enabled();
	if (test_seed) {
		/* DEV-ONLY: 4-word test seed (44-bit, no checksum) so the
		 * brain-phrase flow can be exercised without transcribing a
		 * full BIP39 phrase. Never shipped in production builds. */
		lcd_rect_text(15, 195, 225, 240, "4 words (TEST)", C_FG, C_WARN);
	}
	size_t elen = 0;
	for (;;) {
		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (ui_pt_in(px, py, 15, 250, 115, 300) &&
		    ui_pt_in(rx, ry, 15, 250, 115, 300)) { elen = 16; break; }
		if (ui_pt_in(px, py, 125, 250, 225, 300) &&
		    ui_pt_in(rx, ry, 125, 250, 225, 300)) { elen = 32; break; }
		if (test_seed &&
		    ui_pt_in(px, py, 15, 195, 225, 240) &&
		    ui_pt_in(rx, ry, 15, 195, 225, 240)) { elen = 0; break; }
	}

	/* Optional touch-entropy invitation (design 08 §2.1 S4): the seed
	 * hook samples coordinate-LSB jitter while a finger is held on the
	 * screen. SKIP or 10s idle proceeds with the non-interactive
	 * sources only — never fail-closed. On hold, a 3-2-1 countdown
	 * runs, then seed generation starts automatically — no release
	 * needed; keeping the finger down through it maximizes samples. */
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, "Touch entropy (optional)", C_LBL, C_BG);
	lcd_text_wrap(2, 30, "Press & HOLD the screen anywhere:", C_FG, C_BG);
	lcd_text_wrap(2, 46, "your finger's micro-jitter is mixed", C_FG, C_BG);
	lcd_text_wrap(2, 62, "into the new seed.", C_FG, C_BG);
	lcd_text_wrap(2, 82, "Keep holding through the countdown.", C_FG, C_BG);
	lcd_rect_text(15, 250, 115, 300, "SKIP", C_FG, C_BTN);
	{
		TickType_t t0 = xTaskGetTickCount();
		for (;;) {
			int px, py;
			if (ui_touch_now(&px, &py)) {
				if (ui_pt_in(px, py, 15, 250, 115, 300)) {
					int rx = px, ry = py;
					ui_wait_release(&rx, &ry);
				} else {
					for (int s = 3; s >= 1; s--) {
						char cd[24];
						snprintf(cd, sizeof cd,
						         "Keep holding... %d", s);
						lcd_rect(0, 110, 240, 200, C_BG);
						lcd_line_big(10, 140, cd, C_LBL, C_BG);
						vTaskDelay(pdMS_TO_TICKS(1000));
					}
				}
				break;   /* SKIP tapped, or countdown finished */
			}
			if (xTaskGetTickCount() - t0 > pdMS_TO_TICKS(10000))
				break;
			vTaskDelay(pdMS_TO_TICKS(10));
		}
	}

	esp_fill_random(host, sizeof(host));
	if (os_seed_generate(host, sizeof(host), seed32) != 0) {
		lcd_text_wrap(2, 10, "seed gen failed", C_ERR, C_BG);
		return;
	}

	/* The entropy-hold finger may still be down — drain it so the
	 * mnemonic walkthrough's first ui_wait_press is not skipped. */
	{
		int hx, hy;
		ui_wait_release(&hx, &hy);
	}

	if (elen == 0) {
		/* DEV-ONLY 4-word test mnemonic: 4 uniform wordlist draws, NO
		 * BIP39 checksum. 44 bits of entropy — trivially brute-forceable,
		 * test builds only. The KDF does not care about validity. */
		size_t off = 0;
		mnemonic[0] = '\0';
		for (int i = 0; i < 4; i++) {
			uint32_t idx = os_rng_uniform(2048);
			off += snprintf(mnemonic + off, sizeof(mnemonic) - off,
			                "%s%s", i ? " " : "",
			                os_bip39_word_at((int)idx));
		}
	} else {
		/* 24-word uses all 32 bytes; 12-word uses the first 16 bytes of
		 * the same strong entropy. */
		os_bip39_entropy_to_mnemonic(seed32, elen,
		                             mnemonic, sizeof(mnemonic));
	}

	/* 1. Walk the user through the phrase one word at a time. Each screen
	 * shows a single word large enough to read; the user records it and
	 * taps Next to reveal the next one. */
	if (screen_show_words(mnemonic) != 0) {
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		return;
	}

	/* 2. No passphrase prompt at provisioning. In the TREZOR model the
	 * stored root is the passphrase-LESS base seed; a passphrase is folded
	 * in at every boot via se->derive_session() and never persisted. */

	/* 3. Mandatory second confirmation: re-enter the phrase word-by-word
	 * and check it matches what was shown. A misrecorded seed becomes a
	 * permanently unrecoverable wallet, so a mismatch does NOT advance —
	 * the user is sent back to review the words and must re-confirm until
	 * it matches. The only way out is an explicit abort (which leaves the
	 * device uninitialized), never a silent skip. */
	for (;;) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Verify: re-enter the phrase", C_LBL, C_BG);
		ui_wait_ack();
		char reenter[OS_BIP39_MNEMONIC_MAX];
		int crc = kp_capture_phrase("CONFIRM PHRASE", reenter,
		                            (int)sizeof(reenter));
		if (crc == 0 && strcmp(reenter, mnemonic) == 0) {
			os_secure_bzero(reenter, sizeof(reenter));
			break;                       /* confirmed — proceed */
		}
		os_secure_bzero(reenter, sizeof(reenter));
		/* mismatch (or aborted): tell the user, offer review-retry or a
		 * conscious abort. Do NOT advance on a wrong phrase. */
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Phrase does NOT match.", C_ERR, C_BG);
		lcd_text_wrap(2, 40, "Review words and retry.", C_WARN, C_BG);
		lcd_rect_text(15, 250, 145, 300, "RETRY", C_FG, C_BTN);
		lcd_rect_text(155, 250, 225, 300, "ABORT", C_FG, C_ERR);
		for (;;) {
			int px, py;
			ui_wait_press(&px, &py);
			int rx = px, ry = py;
			ui_wait_release(&rx, &ry);
			if (ui_pt_in(px, py, 155, 250, 225, 300) &&
			    ui_pt_in(rx, ry, 155, 250, 225, 300)) {
				os_secure_bzero(seed32, sizeof(seed32));
				os_secure_bzero(mnemonic, sizeof(mnemonic));
				return;                  /* explicit abort, uninitialized */
			}
			if (ui_pt_in(px, py, 15, 250, 145, 300) &&
			    ui_pt_in(rx, ry, 15, 250, 145, 300))
				break;                   /* retry */
		}
		/* re-show the words before the next confirmation attempt */
		if (screen_show_words(mnemonic) != 0) {
			os_secure_bzero(seed32, sizeof(seed32));
			os_secure_bzero(mnemonic, sizeof(mnemonic));
			return;
		}
	}

	os_bip39_mnemonic_to_seed(mnemonic, NULL, seed64);

	lcd_fill(C_BG);
	/* PIN is optional in DEV-ONLY no-PIN builds: nothing to set. */
	if (!os_dev_no_pin_enabled()) {
		char pin[OS_PIN_MAX_LEN + 1];
		int pin_len = ui_set_pin(pin, sizeof(pin));
		if (pin_len < 0) {
			os_secure_bzero(seed32, sizeof(seed32));
			os_secure_bzero(seed64, sizeof(seed64));
			os_secure_bzero(mnemonic, sizeof(mnemonic));
			lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
			return;
		}
		se->set_pin((const uint8_t *)pin, (size_t)pin_len);
		os_secure_bzero(pin, sizeof(pin));
	}

	int rc = se->store_seed(seed64);
	lcd_fill(C_BG);
	if (rc != SE_OK) {
		lcd_text_wrap(2, 10, "store seed failed", C_ERR, C_BG);
	} else {
		lcd_text_wrap(2, 10, "Initialized OK. Seed stored.", C_OK, C_BG);
		ui_wait_ack();
	}
	os_secure_bzero(seed32, sizeof(seed32));
	os_secure_bzero(seed64, sizeof(seed64));
	os_secure_bzero(host, sizeof(host));
	os_secure_bzero(mnemonic, sizeof(mnemonic));
}

void screen_run_recover(void)
{
	const se_driver_t *se = se_active();
	bool initd;
	se->is_initialized(&initd);
	if (initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Already initialized. Factory-reset first.", C_WARN, C_BG);
		return;
	}

	/* Word-by-word mnemonic entry. Each BIP39 word is uniquely identified by
	 * its first 4 letters, so the user swipes a short prefix and the keypad
	 * auto-resolves it to the full lowercase word. The returned phrase is
	 * already lowercase BIP39 words separated by spaces. */
	char mnemonic[OS_BIP39_MNEMONIC_MAX];
	if (kp_capture_phrase("RECOVER PHRASE", mnemonic, (int)sizeof(mnemonic)) != 0) {
		lcd_text_wrap(2, 100, "cancelled", C_FG, C_BG);
		return;
	}

	/* Validate checksum + recover the original entropy (used only to confirm
	 * the mnemonic is well-formed; the provisioned key is the BIP39 seed).
	 * DEV-ONLY: a 4-word test seed has no checksum — skip validation when
	 * the test-seed build flag is on and the phrase has exactly 4 words. */
	int wc = mnemonic[0] ? 1 : 0;
	for (const char *p = mnemonic; *p; p++)
		if (*p == ' ') wc++;
	bool skip_check = os_dev_test_seed_enabled() && wc == 4;
	if (!skip_check) {
		uint8_t seed32[OS_SEED_LEN];
		memset(seed32, 0, sizeof seed32);
		size_t elen = os_bip39_mnemonic_to_entropy(mnemonic, seed32,
		                                           sizeof(seed32));
		if (elen == 0) {
			os_secure_bzero(seed32, sizeof(seed32));
			os_secure_bzero(mnemonic, sizeof(mnemonic));
			lcd_fill(C_BG);
			lcd_text_wrap(2, 10, "Invalid mnemonic.", C_ERR, C_BG);
			return;
		}
		os_secure_bzero(seed32, sizeof(seed32));
	}

	lcd_fill(C_BG);
	/* PIN is optional in DEV-ONLY no-PIN builds: nothing to set. */
	if (!os_dev_no_pin_enabled()) {
		char pin[OS_PIN_MAX_LEN + 1];
		int pin_len = ui_set_pin(pin, sizeof(pin));
		if (pin_len < 0) {
			os_secure_bzero(mnemonic, sizeof(mnemonic));
			lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
			return;
		}
		se->set_pin((const uint8_t *)pin, (size_t)pin_len);
		os_secure_bzero(pin, sizeof(pin));
	}

	/* No passphrase prompt at provisioning. In the TREZOR model the stored
	 * root is the passphrase-LESS base seed; a passphrase is folded in at
	 * every boot via se->derive_session() and never persisted. */

	uint8_t seed64[OS_BIP39_SEED_LEN];
	os_bip39_mnemonic_to_seed(mnemonic, NULL, seed64);

	int rc = se->store_seed(seed64);
	os_secure_bzero(seed64, sizeof(seed64));
	os_secure_bzero(mnemonic, sizeof(mnemonic));

	lcd_fill(C_BG);
	if (rc != SE_OK) {
		lcd_text_wrap(2, 10, "store seed failed", C_ERR, C_BG);
	} else {
		lcd_text_wrap(2, 10, "Recovered. Seed stored.", C_OK, C_BG);
		ui_wait_ack();
	}
}

void screen_run_about(void)
{
	lcd_fill(C_BG);
	lcd_line(2, 2, "ABOUT", C_LBL, C_BG);

	esp_chip_info_t ci;
	esp_chip_info(&ci);
	const char *model = "ESP32";
	switch (ci.model) {
	case CHIP_ESP32S3: model = "ESP32-S3"; break;
	default: break;
	}
	char line[48];
	snprintf(line, sizeof line, "Chip %s", model);
	lcd_line(2, 22, line, C_FG, C_BG);

	uint32_t flash = 0;
	if (esp_flash_get_size(NULL, &flash) == ESP_OK)
		snprintf(line, sizeof line, "Flash %d MB", (int)(flash >> 20));
	else
		snprintf(line, sizeof line, "Flash unknown");
	lcd_line(2, 36, line, C_FG, C_BG);

	snprintf(line, sizeof line, "Cores %d", ci.cores);
	lcd_line(2, 50, line, C_FG, C_BG);

	/* semantic version + git commit (from the app descriptor, so the
	 * on-device screen can always be matched to the exact source build) */
	snprintf(line, sizeof line, "Firmware " HARDID_FW_VERSION);
	lcd_line(2, 64, line, C_FG, C_BG);

	const esp_app_desc_t *ad = esp_app_get_description();
	snprintf(line, sizeof line, "Build %s", ad->version);
	lcd_line(2, 78, line, C_FG, C_BG);

	ui_wait_ack();
}

/* Per-app action page: SIGN (delegate flow) / DELETE (optional apps only)
 * / BACK. Core apps are pre-installed and cannot be deleted. */
static void screen_app_action(const os_app *app)
{
	for (;;) {
		lcd_fill(C_BG);
		lcd_line(2, 2, app->name, C_LBL, C_BG);
		char line[48];
		snprintf(line, sizeof line, "id %s coin %" PRIu32,
		         app->app_id, app->coin_type);
		lcd_line(2, 18, line, C_DIM, C_BG);
		snprintf(line, sizeof line, "v%" PRIu32 " %s", app->version,
		         app->is_core ? "CORE (preinstalled)" : "installed");
		lcd_line(2, 32, line, C_DIM, C_BG);

		lcd_rect_text(15, 240, 225, 278, "SIGN", C_FG, C_BTN);
		if (!app->is_core)
			lcd_rect_text(15, 288, 100, 318, "DELETE", C_FG, C_ERR);
		lcd_rect_text(140, 288, 225, 318, "BACK", C_FG, C_BTN);

		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;

		if (ui_pt_in(px, py, 15, 240, 225, 278)) {
			screen_run_sign_for_app(app);
			return;
		}
		if (!app->is_core && ui_pt_in(px, py, 15, 288, 100, 318)) {
			lcd_fill(C_BG);
			lcd_text_wrap(2, 10, "Delete this app?", C_WARN, C_BG);
			lcd_rect_text(15, 250, 110, 300, "DELETE", C_FG, C_ERR);
			lcd_rect_text(130, 250, 225, 300, "CANCEL", C_FG, C_BTN);
			for (;;) {
				int qx, qy;
				ui_wait_press(&qx, &qy);
				int qrx = qx, qry = qy;
				ui_wait_release(&qrx, &qry);
				if (ui_pt_in(qx, qy, 15, 250, 110, 300) &&
				    ui_pt_in(qrx, qry, 15, 250, 110, 300)) {
					os_app_uninstall(app->app_id);
					return;
				}
				if (ui_pt_in(qx, qy, 130, 250, 225, 300) &&
				    ui_pt_in(qrx, qry, 130, 250, 225, 300))
					break;                 /* cancel → action page */
			}
			continue;
		}
		if (ui_pt_in(px, py, 140, 288, 225, 318))
			return;                          /* BACK */
	}
}

/* Catalog picker: list officially reviewed apps not yet installed, OK to
 * install, BACK to return. */
static void screen_app_install(void)
{
	size_t gsel = 0;
	for (;;) {
		/* build the not-yet-installed subset */
		const os_app *avail[OS_APP_MAX_INSTALLED];
		size_t na = 0;
		for (size_t i = 0; i < os_app_catalog_count(); i++) {
			const os_app *c = os_app_catalog_at(i);
			if (c && !os_app_by_id(c->app_id))
				avail[na++] = c;
		}
		if (gsel >= na && na > 0)
			gsel = na - 1;

		lcd_fill(C_BG);
		lcd_line(2, 2, "INSTALL APP", C_LBL, C_BG);
		if (na == 0) {
			lcd_text_wrap(2, 30, "All catalog apps installed.", C_DIM, C_BG);
		} else {
			int y = 34;
			for (size_t i = 0; i < na; i++) {
				char line[48];
				snprintf(line, sizeof line, "%s (coin %" PRIu32 ")",
				         avail[i]->name, avail[i]->coin_type);
				if (i == gsel) {
					lcd_rect(0, y - 1, 240, y + 15, C_BTN);
					lcd_line(2, y, line, C_FG, C_BTN);
				} else {
					lcd_line(2, y, line, C_FG, C_BG);
				}
				y += 16;
			}
		}

		lcd_rect_text(15, 288, 70, 318, "<", C_FG, C_BTN);
		lcd_rect_text(15, 288, 70, 318, "<", C_FG, C_BTN);
		lcd_rect_text(80, 288, 160, 318, "OK", C_FG, C_BTN);
		lcd_rect_text(170, 288, 225, 318, ">", C_FG, C_BTN);

		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;

		if (ui_pt_in(px, py, 15, 288, 70, 318)) {
			/* < : cursor up; on the first entry → BACK to the app list */
			if (gsel > 0) gsel--;
			else return;
		} else if (ui_pt_in(px, py, 170, 288, 225, 318)) {
			/* > : cursor down through the catalog */
			if (gsel + 1 < na) gsel++;
		} else if (ui_pt_in(px, py, 80, 288, 160, 318)) {
			if (na > 0) {
				const os_app *pick = avail[gsel];
				if (os_app_catalog_install(pick->app_id) == 0) {
					/* feedback + debounce: show what was installed, then
					 * wait for a FULL release and a cooldown so one press
					 * can never cascade into installing several apps. */
					lcd_fill(C_BG);
					lcd_line(2, 2, "INSTALLED", C_OK, C_BG);
					lcd_text_wrap(2, 30, pick->name, C_FG, C_BG);
					ui_wait_release(&rx, &ry);
					vTaskDelay(pdMS_TO_TICKS(350));
				}
				/* stay; the installed app drops out of the list */
			}
		}
	}
}

void screen_run_apps(void)
{
	/* V2.0 App market: list installed apps (core BTC/ETH + runtime
	 * installed). The UI is intentionally minimal — name, coin, version,
	 * state — and tapping an app runs the sign delegation flow for it.
	 * Third-party install/uninstall is driven from the host side
	 * (link_esp / host-tools); this screen is the on-device view. */
	lcd_fill(C_BG);
	lcd_line(2, 2, "APP MARKET", C_LBL, C_BG);
	lcd_line(2, 16, "OK: manage  [+]: install", C_DIM, C_BG);

	const size_t per = 7;              /* rows on a 240x320 screen */
	size_t gsel = 0;                   /* absolute selected row index */

	for (;;) {
		/* re-read the live count each pass so apps installed via the
		 * catalog (or deleted) appear/disappear immediately. */
		const size_t n = os_app_count();
		/* selectable rows = installed apps + one "[+ INSTALL APP]" row */
		const size_t total = n + 1;
		if (gsel >= total)
			gsel = total - 1;
		size_t page = gsel / per;
		size_t sel = gsel % per;
		size_t pages = (total + per - 1) / per;

		lcd_fill(C_BG);
		lcd_line(2, 2, "APP MARKET", C_LBL, C_BG);
		char head[48];
		snprintf(head, sizeof head, "page %zu/%zu", page + 1,
		         pages > 0 ? pages : 1);
		lcd_line(2, 16, head, C_DIM, C_BG);

		size_t rows = 0;
		int y = 34;
		for (size_t i = page * per; i < total && i < (page + 1) * per; i++) {
			char line[48];
			uint16_t fg = C_FG;
			if (i < n) {
				const os_app *a = os_app_at(i);
				if (!a) break;
				/* [C]=preinstalled core, [+]=optional installed */
				snprintf(line, sizeof line, "%s %s%s v%" PRIu32,
				         a->is_core ? "[C]" : "[+]",
				         a->state == OS_APP_SUSPENDED ? "!" : "",
				         a->name, a->version);
				fg = (a->state == OS_APP_SUSPENDED) ? C_ERR : C_FG;
			} else {
				snprintf(line, sizeof line, "+ INSTALL APP");
				fg = C_OK;
			}
			if (rows == sel) {
				lcd_rect(0, y - 1, 240, y + 15, C_BTN);
				lcd_line(2, y, line, C_FG, C_BTN);
			} else {
				lcd_line(2, y, line, fg, C_BG);
			}
			y += 16;
			rows++;
		}

		lcd_line(2, y + 4, "< > move cursor, OK select", C_DIM, C_BG);

		/* bottom nav bar: < | OK | >. Left/right move the cursor across
		 * apps AND the install row; OK opens the app action page (or the
		 * installer). On the first row, < exits to the main menu. */
		lcd_rect_text(15, 288, 70, 318, "<", C_FG, C_BTN);
		lcd_rect_text(80, 288, 160, 318, "OK", C_FG, C_BTN);
		lcd_rect_text(170, 288, 225, 318, ">", C_FG, C_BTN);

		int px, py;
		if (!ui_wait_press(&px, &py))
			continue;
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;

		/* bottom nav bar */
		if (py >= 288) {
			if (ui_pt_in(px, py, 15, 288, 70, 318)) {
				if (gsel > 0) gsel--;
				else { lcd_fill(C_BG); return; }
			} else if (ui_pt_in(px, py, 170, 288, 225, 318)) {
				if (gsel + 1 < total) gsel++;
			} else if (ui_pt_in(px, py, 80, 288, 160, 318)) {
				if (gsel < n) {
					const os_app *a = os_app_at(gsel);
					if (a) screen_app_action(a);
				} else {
					screen_app_install();
				}
			}
			continue;
		}

		/* tap on a row → move cursor there and open it directly */
		size_t row = (size_t)((py - 34) / 16);
		size_t idx = page * per + row;
		if (row < rows && idx < total) {
			gsel = idx;
			if (idx < n) {
				const os_app *a = os_app_at(idx);
				if (a) screen_app_action(a);
			} else {
				screen_app_install();
			}
		}
	}
}