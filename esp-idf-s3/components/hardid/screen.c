/*
 * HardID — device screen flows (initialize / sign / factory reset)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "esp_random.h"

#include "display.h"
#include "boot.h"
#include "pin.h"
#include "se_driver.h"
#include "seed.h"
#include "bip39.h"
#include "secure_zero.h"
#include "inter.h"
#include "keypad.h"
#include "screen.h"

/* mock-SE helpers (se_mock.c); a real backend exposes wipe via se_driver_t */
void se_mock_reset(void);
void se_mock_set_pin(const uint8_t *pin, size_t len);

void screen_run_sign(void)
{
	const se_driver_t *se = se_active();
	uint8_t digest[32], sig[64];
	memset(digest, 0x11, sizeof(digest));

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

	uint8_t recid;
	int r = se->sign_digest(NULL, 0, digest, sig, &recid);
	lcd_fill(C_BG);
	if (r != SE_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "sign failed rc=%d", r);
		lcd_text_wrap(2, 10, msg, C_ERR, C_BG);
		return;
	}
	lcd_line(2, 2, "Signature (r||s)", C_LBL, C_BG);
	char hex[130];
	for (int i = 0; i < 64; i++)
		snprintf(hex + i * 2, 3, "%02x", sig[i]);
	lcd_text_wrap(2, 16, hex, C_FG, C_BG);
	ui_wait_ack();
}

void screen_run_factory_reset(void)
{
	if (!ui_confirm("Wipe device? Seed + PIN will be erased.")) {
		lcd_text_wrap(2, 100, "cancelled", C_FG, C_BG);
		return;
	}
	se_mock_reset();
	os_board_display_home();
	lcd_text_wrap(2, 60, "Device wiped. Re-initialize to set a seed.", C_OK, C_BG);
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
	os_bip39_mnemonic_to_seed(mnemonic, NULL, seed64);
	lcd_fill(C_BG);
	lcd_line(2, 2, "Recovery phrase", C_LBL, C_BG);
	lcd_text_wrap(2, 16, mnemonic, C_FG, C_BG);
	if (!ui_confirm_overlay()) {
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(seed64, sizeof(seed64));
		return;
	}

	lcd_fill(C_BG);
	char pin[OS_PIN_MAX_LEN + 1];
	int pin_len = ui_set_pin(pin, sizeof(pin));
	if (pin_len < 0) {
		lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
		return;
	}
	se_mock_set_pin((const uint8_t *)pin, (size_t)pin_len);
	os_secure_bzero(pin, sizeof(pin));

	int rc = se->store_seed(seed32);
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
}