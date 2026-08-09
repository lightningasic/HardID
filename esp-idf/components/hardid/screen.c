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

#include "display.h"
#include "boot.h"
#include "pin.h"
#include "se_driver.h"
#include "seed.h"
#include "bip39.h"
#include "secure_zero.h"
#include "inter.h"
#include "keypad.h"
#include "app.h"
#include "signsvc.h"
#include "screen.h"

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
static bool screen_confirm_intent(const os_tx_intent *it)
{
	lcd_fill(C_BG);
	lcd_line(2, 2, "CONFIRM", C_LBL, C_BG);
	char line[48];

	if (it->kind == OS_INTENT_UNKNOWN) {
		lcd_text_wrap(2, 18, "UNKNOWN CALL", C_ERR, C_BG);
		lcd_text_wrap(2, 34, "Not parseable. Tap twice to sign.", C_WARN, C_BG);
		ui_wait_ack();
		ui_wait_ack();
		return true;
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

	if (it->amount_token[0])
		snprintf(line, sizeof line, "amount %.10s %.10s",
		         it->amount_token, it->symbol);
	else
		snprintf(line, sizeof line, "amount %llu %.10s",
		         (unsigned long long)it->amount, it->symbol);
	lcd_line(2, 44, line, C_FG, C_BG);

	if (it->method[0]) {
		snprintf(line, sizeof line, "method %s", it->method);
		lcd_line(2, 58, line, C_FG, C_BG);
	}
	snprintf(line, sizeof line, "max fee %llu",
	         (unsigned long long)it->fee_limit);
	lcd_line(2, 72, line, C_FG, C_BG);

	lcd_line(2, 100, "tap to CONFIRM", C_LBL, C_BG);
	ui_wait_ack();
	return true;
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

	/* V2.0: delegate signing through signsvc with the on-screen confirm
	 * hook. A sample tx is synthesized on-device for the bring-up build;
	 * the real tx arrives via HOST LINK / App market install flow. */
	uint8_t tx[256];
	uint32_t path[3] = { 0x80000000u | 44,
	                    0x80000000u | app->coin_type, 0 };
	size_t tx_len = 0;

	if (app->coin_type == 60) {
		/* minimal legacy EVM transfer built with correct RLP:
		 * [nonce=1, gasPrice=20, gasLimit=21000, to=0x11..11,
		 *  value=1000, data=] */
		uint8_t tmp[64]; size_t o = 0;
		tmp[o++] = 0x01;                          /* nonce 1 */
		tmp[o++] = 0x14;                          /* gasPrice 20 */
		tmp[o++] = 0x82; tmp[o++] = 0x52; tmp[o++] = 0x08; /* gas=21000 */
		tmp[o++] = 0x94;                          /* 20-byte string hdr */
		for (int i = 0; i < 20; i++) tmp[o++] = 0x11;
		tmp[o++] = 0x82; tmp[o++] = 0x03; tmp[o++] = 0xe8; /* value=1000 */
		tmp[o++] = 0x80;                          /* empty data */
		tx[0] = (uint8_t)(0xc0 + o);             /* list hdr */
		memcpy(tx + 1, tmp, o);
		tx_len = 1 + o;
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
		lcd_line(2, 2, "Signature (r||s)", C_LBL, C_BG);
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
	char pin[OS_PIN_MAX_LEN + 1];
	int pin_len;
	if (initd) {
		/* a PIN exists: entering the correct one proves ownership */
		lcd_fill(C_BG);
		pin_len = ui_enter_pin(pin, sizeof(pin));
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
	} else {
		/* no PIN ever set: force one before allowing a wipe so the
		 * device cannot be wiped while unprotected */
		lcd_fill(C_BG);
		pin_len = ui_set_pin(pin, sizeof(pin));
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
	lcd_text_wrap(2, 10, "Enable passphrase?", C_WARN, C_BG);
	if (!ui_confirm_yesno())
		return 0;

	for (;;) {
		lcd_fill(C_BG);
		if (kp_capture_alpha("PASSPHRASE", out, (int)out_max) != 0)
			return -1;
		if (out[0] == '\0')
			return 0;   /* typed nothing -> no passphrase */

		char again[OS_BIP39_MNEMONIC_MAX];
		again[0] = '\0';
		lcd_fill(C_BG);
		if (kp_capture_alpha("CONFIRM PASSPHRASE", again,
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

	esp_fill_random(host, sizeof(host));
	if (os_seed_generate(host, sizeof(host), seed32) != 0) {
		lcd_text_wrap(2, 10, "seed gen failed", C_ERR, C_BG);
		return;
	}

	os_bip39_entropy_to_mnemonic(seed32, sizeof(seed32),
	                             mnemonic, sizeof(mnemonic));

	/* 1. Walk the user through the phrase one word at a time. Each screen
	 * shows a single word large enough to read; the user records it and
	 * taps Next to reveal the next one. */
	if (screen_show_words(mnemonic) != 0) {
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		return;
	}

	/* 2. Optional BIP39 passphrase. Empty yields the plain seed; a
	 * non-empty one yields a distinct key that must be re-entered on every
	 * unlock, so ask up front and require a confirmation re-entry. */
	char passphrase[OS_BIP39_MNEMONIC_MAX];
	passphrase[0] = '\0';
	int prc = prompt_passphrase(passphrase, sizeof(passphrase));
	if (prc < 0) {
		os_secure_bzero(passphrase, sizeof(passphrase));
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		return;
	}

	/* 3. Second confirmation: re-enter the phrase word-by-word and check
	 * it matches what was shown. Prevents a misrecorded seed from becoming
	 * a permanently unrecoverable wallet. */
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, "Verify the phrase:", C_LBL, C_BG);
	char reenter[OS_BIP39_MNEMONIC_MAX];
	if (kp_capture_phrase("CONFIRM PHRASE", reenter,
	                      (int)sizeof(reenter)) != 0 ||
	    strcmp(reenter, mnemonic) != 0) {
		os_secure_bzero(reenter, sizeof(reenter));
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(seed64, sizeof(seed64));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Phrase mismatch!", C_ERR, C_BG);
		return;
	}
	os_secure_bzero(reenter, sizeof(reenter));

	os_bip39_mnemonic_to_seed(mnemonic,
	                          (passphrase[0] != '\0') ? passphrase : NULL,
	                          seed64);
	os_secure_bzero(passphrase, sizeof(passphrase));

	lcd_fill(C_BG);
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

	int rc = se->store_seed(seed64);
	lcd_fill(C_BG);
	if (rc != SE_OK) {
		lcd_text_wrap(2, 10, "store seed failed", C_ERR, C_BG);
	} else {
		lcd_text_wrap(2, 10, "Initialized OK. Seed + PIN stored.", C_OK, C_BG);
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
	 * the mnemonic is well-formed; the provisioned key is the BIP39 seed). */
	uint8_t seed32[OS_SEED_LEN];
	memset(seed32, 0, sizeof seed32);
	size_t elen = os_bip39_mnemonic_to_entropy(mnemonic, seed32, sizeof(seed32));
	if (elen == 0) {
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Invalid mnemonic.", C_ERR, C_BG);
		return;
	}
	os_secure_bzero(seed32, sizeof(seed32));

	lcd_fill(C_BG);
	char pin[OS_PIN_MAX_LEN + 1];
	int pin_len = ui_set_pin(pin, sizeof(pin));
	if (pin_len < 0) {
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
		return;
	}
	se->set_pin((const uint8_t *)pin, (size_t)pin_len);
	os_secure_bzero(pin, sizeof(pin));

	/* Optional BIP39 passphrase. An empty passphrase yields the plain seed;
	 * a non-empty one yields a distinct key, so it must be re-entered on
	 * repeat unlocks. Ask first so "skip" is a single tap, and require a
	 * confirmation re-entry so a typo can't lock the wallet to a wrong key. */
	char passphrase[OS_BIP39_MNEMONIC_MAX];
	passphrase[0] = '\0';
	if (prompt_passphrase(passphrase, sizeof(passphrase)) < 0) {
		os_secure_bzero(passphrase, sizeof(passphrase));
		os_secure_bzero(mnemonic, sizeof(mnemonic));
		return;
	}

	uint8_t seed64[OS_BIP39_SEED_LEN];
	os_bip39_mnemonic_to_seed(mnemonic,
	                          (passphrase[0] != '\0') ? passphrase : NULL,
	                          seed64);
	os_secure_bzero(passphrase, sizeof(passphrase));

	int rc = se->store_seed(seed64);
	os_secure_bzero(seed64, sizeof(seed64));
	os_secure_bzero(mnemonic, sizeof(mnemonic));

	lcd_fill(C_BG);
	if (rc != SE_OK) {
		lcd_text_wrap(2, 10, "store seed failed", C_ERR, C_BG);
	} else {
		lcd_text_wrap(2, 10, "Recovered. Seed + PIN stored.", C_OK, C_BG);
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

	snprintf(line, sizeof line, "Firmware " HARDID_FW_VERSION);
	lcd_line(2, 64, line, C_FG, C_BG);

	ui_wait_ack();
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
	lcd_line(2, 16, "select app to sign", C_DIM, C_BG);

	const size_t n = os_app_count();
	const size_t per = 7;              /* rows on a 240x320 screen */
	const size_t pages = (n + per - 1) / per;
	size_t page = 0;

	for (;;) {
		lcd_fill(C_BG);
		lcd_line(2, 2, "APP MARKET", C_LBL, C_BG);
		char head[48];
		snprintf(head, sizeof head, "page %zu/%zu", page + 1,
		         pages > 0 ? pages : 1);
		lcd_line(2, 16, head, C_DIM, C_BG);
		lcd_line(2, 26, "tap title to EXIT", C_DIM, C_BG);

		int y = 34;
		for (size_t i = page * per; i < n && i < (page + 1) * per; i++) {
			const os_app *a = os_app_at(i);
			if (!a) break;
			char line[48];
			snprintf(line, sizeof line, "%s %s v%" PRIu32,
			         a->state == OS_APP_SUSPENDED ? "! " : "  ",
			         a->name, a->version);
			lcd_line(2, y, line,
			         a->state == OS_APP_SUSPENDED ? C_ERR : C_FG, C_BG);
			y += 16;
		}

		lcd_line(2, y + 4, "< > switch page, tap app", C_DIM, C_BG);

		int px, py;
		if (!ui_wait_press(&px, &py))
			continue;
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;

		/* tap on the header title → exit back to the main menu */
		if (py < 30) {
			lcd_fill(C_BG);
			return;
		}

		/* page nav zones at the bottom corners */
		if (py > 260) {
			if (px < 120 && page > 0)
				page--;
			else if (px >= 120 && page + 1 < pages)
				page++;
			continue;
		}

		/* tap on an app row → sign with it */
		size_t row = (size_t)((py - 34) / 16);
		size_t idx = page * per + row;
		if (idx < n) {
			const os_app *a = os_app_at(idx);
			if (a && a->state != OS_APP_SUSPENDED) {
				screen_run_sign_for_app(a);
				/* redraw list after returning */
			}
		}
	}
}