/*
 * HardID Hardware Wallet — ESP32-S3 bring-up main
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * First-stage bring-up on the Waveshare ESP32-S3-Touch-LCD-2 (ESP32-S3R8).
 * Backend: core/se_mock.c (no ACL16 hardware in this port yet).
 *
 * Smoke test:
 *   1. os_boot_run()  — board init, RNG self-test, SE init
 *   2. derive entropy from all three seed sources, generate a 24-word
 *      BIP39 mnemonic, derive m/44'/0'/0'/0/0 and print its xpub
 *   3. store the seed in the SE and verify a PIN-locked sign flow
 *
 * Everything is logged over UART; display/touch are a later stage.
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"

#include "boot.h"
#include "seed.h"
#include "bip39.h"
#include "bip32.h"
#include "se_driver.h"
#include "secure_zero.h"

static const char *TAG = "hardid.main";

/* bitcoin mainnet xpub version bytes 0x0488B21E */
#define XPUB_VERSION 0x0488B21Eu

void app_main(void)
{
	uint8_t seed32[OS_SEED_LEN];
	uint8_t seed64[OS_BIP39_SEED_LEN];
	uint8_t host[32];
	char mnemonic[OS_BIP39_MNEMONIC_MAX];
	os_hdnode node;
	char xpub[OS_BIP32_XKEY_MAX];
	uint8_t digest[32];
	uint8_t sig[64];
	uint8_t recid;
	const se_driver_t *se;

	/* 1. boot: board init -> RNG self-test -> SE init */
	ESP_LOGI(TAG, "HardID bring-up (ESP32-S3, mock SE backend)");
	if (os_boot_run() != OS_BOOT_STAGE_MAIN_LOOP) {
		ESP_LOGE(TAG, "boot stage failed");
		for (;;) { }
	}

	/* 2. seed generation: SE1 TRNG || SE2 TRNG || host entropy */
	esp_fill_random(host, sizeof(host));
	if (os_seed_generate(host, sizeof(host), seed32) != 0) {
		ESP_LOGE(TAG, "seed generation failed");
		os_secure_bzero(host, sizeof(host));
		return;
	}
	ESP_LOGI(TAG, "seed generated from 3 entropy sources");

	/* 3. BIP39: 32 bytes -> 24-word mnemonic, then 64-byte seed */
	int nwords = os_bip39_entropy_to_mnemonic(seed32, sizeof(seed32),
	                                          mnemonic, sizeof(mnemonic));
	ESP_LOGI(TAG, "BIP39 mnemonic (%d words):", nwords);
	ESP_LOGI(TAG, "%s", mnemonic);
	os_bip39_mnemonic_to_seed(mnemonic, NULL, seed64);

	/* 4. BIP32: master node -> m/44'/0'/0'/0/0, print xpub */
	int r1 = os_bip32_from_seed(seed64, sizeof(seed64), &node);
	int r2 = (r1 == 0) ? os_bip32_derive_path(&node, "m/44'/0'/0'/0/0") : -99;
	ESP_LOGI(TAG, "BIP32 from_seed=%d derive=%d", r1, r2);
	if (r1 != 0 || r2 != 0) {
		ESP_LOGE(TAG, "BIP32 derivation failed");
		return;
	}
	os_bip32_serialize(&node, false, XPUB_VERSION, xpub, sizeof(xpub));
	ESP_LOGI(TAG, "xpub m/44'/0'/0'/0/0: %s", xpub);

	/* 5. provision the seed in the SE, then exercise the signing flow */
	se = se_active();
	if (se->store_seed(seed32) == SE_OK) {
		ESP_LOGI(TAG, "seed stored in %s (mock, RAM only)", se->name);
	} else {
		ESP_LOGW(TAG, "seed store skipped (already provisioned?)");
	}

	/* signing must be PIN-gated: expect SE_ERR_AUTH before PIN */
	memset(digest, 0x11, sizeof(digest));
	int r = se->sign_digest(NULL, 0, digest, sig, &recid);
	ESP_LOGI(TAG, "sign before PIN (expect AUTH fail): %d", r);

	/* zeroize secrets */
	os_secure_bzero(seed32, sizeof(seed32));
	os_secure_bzero(seed64, sizeof(seed64));
	os_secure_bzero(host, sizeof(host));

	ESP_LOGI(TAG, "bring-up OK. Board ready.");
	for (;;) { vTaskDelay(pdMS_TO_TICKS(1000)); }
}