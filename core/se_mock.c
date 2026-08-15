/*
 * HardID Hardware Wallet — SE backend registry + mock backend
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * se_mock.c provides a software stand-in used by host-side tests and the
 * emulator. Real backends (se_acl16.c, se_thd89.c) implement the same
 * se_driver_t over SPI/I2C. Exactly one is linked via se_active().
 */

#include "se_driver.h"
#include "secure_zero.h"
#include "sha512.h"
#include "hkdf.h"
#include "secp256r1.h"
#include <string.h>

/* ---- mock backend state (host tests / emulator only) ---- */
static uint8_t  mock_seed_stored;
static uint8_t  mock_seed[64];        /* passphrase-less base seed */
static uint8_t  mock_session[64];     /* volatile derived session seed */
static uint8_t  mock_session_active;  /* session seed in effect */
static uint32_t mock_counter;
static uint32_t mock_rng_seq;
static uint8_t  mock_pin[8];
static size_t   mock_pin_len;
static bool     mock_unlocked;   /* session unlocked by a successful PIN verify */
static uint32_t mock_lock_timeout = 300;  /* auto-lock idle timeout, seconds (0=never) */

/* ---- mock FIDO2 state (design doc 09 §4) ----
 * The FIDO master key, epoch and cred_idx counters live only in the SE.
 * credIDs are opaque self-describing blobs computed and validated here;
 * the MCU only passes them through. Everything is persisted so FIDO
 * credentials survive reboots on the emulator build (RAM-only otherwise). */
static uint32_t mock_fido_epoch;    /* advanced by authenticatorReset (only
                                       invalidates FIDO creds, never seed) */
static uint32_t mock_fido_cred_idx; /* per-credential allocator, NVM-backed */
static uint32_t mock_fido_signcount;/* global assertion counter, NVM-backed */

#if defined(ESP_PLATFORM)
#include "nvs_flash.h"
#include "nvs.h"

/* DEV-ONLY mock persistence. The mock SE is RAM-only by nature, which
 * makes on-device flow walkthroughs impossible: every reboot looks like a
 * blank device, so the brain-phrase gate (boot-time, initialized-only)
 * could never be exercised. Persist the provisioned seed + PIN in NVS so
 * the mock behaves like a real SE across reboots. MOCK BUILDS ONLY — a
 * real SE never lets the seed touch flash. The brain-phrase session seed
 * is deliberately NOT persisted (it must die on power-cycle). */
#define MOCK_NVS_NS "hardid_mock"

static void mock_nvs_save(void)
{
	nvs_handle_t h;
	if (nvs_open(MOCK_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
		return;
	if (mock_seed_stored)
		nvs_set_blob(h, "seed", mock_seed, sizeof mock_seed);
	if (mock_pin_len)
		nvs_set_blob(h, "pin", mock_pin, mock_pin_len);
	nvs_set_u32(h, "fido_epoch", mock_fido_epoch);
	nvs_set_u32(h, "fido_idx", mock_fido_cred_idx);
	nvs_set_u32(h, "fido_sigcnt", mock_fido_signcount);
	nvs_set_u32(h, "lock_timeout", mock_lock_timeout);
	nvs_commit(h);
	nvs_close(h);
}

static void mock_nvs_load(void)
{
	esp_err_t err = nvs_flash_init();
	if (err == ESP_ERR_NVS_NO_FREE_PAGES ||
	    err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
		nvs_flash_erase();
		err = nvs_flash_init();
	}
	if (err != ESP_OK)
		return;
	nvs_handle_t h;
	if (nvs_open(MOCK_NVS_NS, NVS_READONLY, &h) != ESP_OK)
		return;
	size_t len = sizeof mock_seed;
	if (nvs_get_blob(h, "seed", mock_seed, &len) == ESP_OK &&
	    len == sizeof mock_seed)
		mock_seed_stored = 1;
	len = sizeof mock_pin;
	if (nvs_get_blob(h, "pin", mock_pin, &len) == ESP_OK)
		mock_pin_len = len;
	if (nvs_get_u32(h, "fido_epoch", &mock_fido_epoch) != ESP_OK)
		mock_fido_epoch = 0;
	if (nvs_get_u32(h, "fido_idx", &mock_fido_cred_idx) != ESP_OK)
		mock_fido_cred_idx = 0;
	if (nvs_get_u32(h, "fido_sigcnt", &mock_fido_signcount) != ESP_OK)
		mock_fido_signcount = 0;
	if (nvs_get_u32(h, "lock_timeout", &mock_lock_timeout) != ESP_OK)
		mock_lock_timeout = 300;
	nvs_close(h);
}

static void mock_nvs_erase(void)
{
	nvs_handle_t h;
	if (nvs_open(MOCK_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
		return;
	nvs_erase_all(h);
	nvs_commit(h);
	nvs_close(h);
}
#else
static void mock_nvs_save(void)  { }
static void mock_nvs_load(void)  { }
static void mock_nvs_erase(void) { }
#endif


static int mock_init(void) { mock_nvs_load(); return SE_OK; }

static int mock_get_random(uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < len; i++) {
		mock_rng_seq = mock_rng_seq * 1664525u + 1013904223u;
		buf[i] = (uint8_t)(mock_rng_seq >> 24);
	}
	return SE_OK;
}

static int mock_store_seed(const uint8_t *seed64)
{
	if (mock_seed_stored)
		return SE_ERR_STATE;
	memcpy(mock_seed, seed64, 64);
	mock_seed_stored = 1;
	mock_nvs_save();
	return SE_OK;
}

static int mock_is_initialized(bool *init)
{
	*init = mock_seed_stored != 0;
	return SE_OK;
}

static int mock_is_pin_set(bool *set)
{
	*set = mock_pin_len != 0;
	return SE_OK;
}

static int mock_sign_digest(const uint32_t *path, size_t path_len,
                            const uint8_t *digest32,
                            uint8_t *sig64, uint8_t *recid)
{
	/* NOT real ECDSA — deterministic stand-in for plumbing tests only. */
	if (!mock_seed_stored)
		return SE_ERR_STATE;
	/* SECURITY INVARIANT: signing requires the session to be unlocked by a
	 * successful verify_pin. A real SE backend must enforce this in hardware
	 * so the key can never sign without PIN authorization. */
	if (!mock_unlocked)
		return SE_ERR_AUTH;
	(void)path; (void)path_len;
	const uint8_t *k = mock_session_active ? mock_session : mock_seed;
	for (int i = 0; i < 64; i++)
		sig64[i] = digest32[i % 32] ^ k[i] ^ (uint8_t)i;
	if (recid) *recid = 0;
	return SE_OK;
}

static int mock_get_xpub(const uint32_t *path, size_t path_len,
                         char *xpub_out, size_t xpub_max)
{
	(void)path; (void)path_len;
	const char *fake = "xpub6Mock...";
	if (xpub_max < strlen(fake) + 1)
		return SE_ERR_PARAM;
	strcpy(xpub_out, fake);
	return SE_OK;
}

static int mock_verify_pin(const uint8_t *pin, size_t len,
                           uint32_t *wait, bool *is_duress)
{
	(void)wait; (void)is_duress;
	/* reject empty/no-PIN-set: zero-length comparison is vacuously true */
	if (len == 0 || mock_pin_len == 0)
		return SE_ERR_AUTH;
	/* constant-time comparison; real SE backend must do this in hardware */
	if (len == mock_pin_len && os_consttime_eq(pin, mock_pin, len)) {
		mock_unlocked = true;   /* successful verify unlocks the session */
		return SE_OK;
	}
	return SE_ERR_AUTH;
}

static int mock_set_pin(const uint8_t *pin, size_t len)
{
	if (len < 4 || len > sizeof(mock_pin))
		return SE_ERR_PARAM;
	memcpy(mock_pin, pin, len);
	mock_pin_len = len;
	mock_unlocked = false;   /* a (re)set PIN must be verified again */
	mock_nvs_save();
	return SE_OK;
}

static int mock_lock(void)
{
	mock_unlocked = false;
	return SE_OK;
}

static int mock_is_unlocked(bool *unlocked)
{
	*unlocked = mock_unlocked;
	return SE_OK;
}

static int mock_get_lock_timeout(uint32_t *seconds)
{
	*seconds = mock_lock_timeout;
	return SE_OK;
}

static int mock_set_lock_timeout(uint32_t seconds)
{
	mock_lock_timeout = seconds;
	mock_nvs_save();
	return SE_OK;
}

static int mock_wipe(void)
{
	mock_seed_stored = 0;
	memset(mock_seed, 0, sizeof(mock_seed));
	memset(mock_session, 0, sizeof(mock_session));
	mock_session_active = 0;
	mock_counter = 0;
	mock_rng_seq = 1;
	memset(mock_pin, 0, sizeof(mock_pin));
	mock_pin_len = 0;
	mock_unlocked = false;
	mock_fido_epoch = 0;
	mock_fido_cred_idx = 0;
	mock_fido_signcount = 0;
	mock_lock_timeout = 300;   /* factory default auto-lock */
	mock_nvs_erase();
	return SE_OK;
}

static int mock_derive_session(const uint8_t *passphrase, size_t len)
{
	/* Session seed = PBKDF2-HMAC-SHA512(base_seed, "mnemonic" + passphrase),
	 * mirroring the BIP39 salt convention so a recovered device with the
	 * same words + passphrase lands on the same keys. Volatile: kept in
	 * mock RAM only, cleared by wipe, never written to SE NVM. */
	if (!mock_seed_stored)
		return SE_ERR_STATE;
	memset(mock_session, 0, sizeof(mock_session));
	mock_session_active = 0;
	if (len == 0)
		return SE_OK;
	char salt[8 + 256];
	size_t sl = 8;
	memcpy(salt, "mnemonic", 8);
	if (len > sizeof(salt) - sl) len = sizeof(salt) - sl;
	memcpy(salt + sl, passphrase, len);
	sl += len;
	os_pbkdf2_sha512(mock_seed, sizeof(mock_seed),
	                 (const uint8_t *)salt, sl, 2048,
	                 mock_session, sizeof(mock_session));
	mock_session_active = 1;
	return SE_OK;
}

static int mock_policy_authorize(uint32_t pid, uint64_t amount)
{
	(void)pid; (void)amount;
	return SE_ERR_AUTH; /* mock always requires manual confirm */
}

static int mock_mono_read(uint32_t *c)  { *c = mock_counter; return SE_OK; }
static int mock_mono_inc(void)          { mock_counter++; return SE_OK; }

static int mock_attest(const uint8_t *ch32, uint8_t *resp, size_t *resp_len)
{
	for (int i = 0; i < 32; i++) resp[i] = ch32[i] ^ 0x5A;
	*resp_len = 32;
	return SE_OK;
}

/* ---- mock FIDO2 (design doc 09 §4/§5.2) ----
 * Mirror of the KDF a real SE backend implements in hardware:
 *   master  = mock_seed (the SE-internal root; never leaves this file)
 *   priv    = HMAC-SHA256(master, "fido-p256" || epoch || cred_idx)
 *   credID  = epoch(4B BE) || cred_idx(4B BE) || tag(16B)
 *   tag     = HMAC-SHA256(master, "fido-credid" || epoch || cred_idx
 *                         || rp_hash32)[0:16]
 * epoch/cred_idx are NVM-backed so credentials are idempotently
 * re-derivable after reboot. FIDO keys live in this file only. */

static void mock_fido_priv(const uint8_t rp_hash32[32], uint32_t epoch,
                           uint32_t cred_idx, uint8_t priv32[32])
{
	uint8_t info[9 + 4 + 4];
	os_secure_bzero(info, sizeof info);
	memcpy(info, "fido-p256", 9);
	info[9] = (uint8_t)(epoch >> 24);
	info[10] = (uint8_t)(epoch >> 16);
	info[11] = (uint8_t)(epoch >> 8);
	info[12] = (uint8_t)epoch;
	info[13] = (uint8_t)(cred_idx >> 24);
	info[14] = (uint8_t)(cred_idx >> 16);
	info[15] = (uint8_t)(cred_idx >> 8);
	info[16] = (uint8_t)cred_idx;
	(void)rp_hash32;
	os_hmac_sha256(mock_seed, sizeof mock_seed, info, sizeof info, priv32);
	os_secure_bzero(info, sizeof info);
}

static void mock_fido_tag(const uint8_t rp_hash32[32], uint32_t epoch,
                          uint32_t cred_idx, uint8_t tag[16])
{
	/* "fido-credid"(11) || epoch(4 BE) || cred_idx(4 BE) || rp_hash32(32) */
	uint8_t info[11 + 4 + 4 + 32];
	os_secure_bzero(info, sizeof info);
	memcpy(info, "fido-credid", 11);
	info[11] = (uint8_t)(epoch >> 24);
	info[12] = (uint8_t)(epoch >> 16);
	info[13] = (uint8_t)(epoch >> 8);
	info[14] = (uint8_t)epoch;
	info[15] = (uint8_t)(cred_idx >> 24);
	info[16] = (uint8_t)(cred_idx >> 16);
	info[17] = (uint8_t)(cred_idx >> 8);
	info[18] = (uint8_t)cred_idx;
	memcpy(info + 19, rp_hash32, 32);
	uint8_t h[32];
	os_hmac_sha256(mock_seed, sizeof mock_seed, info, sizeof info, h);
	memcpy(tag, h, 16);
	os_secure_bzero(info, sizeof info);
	os_secure_bzero(h, sizeof h);
}

static int mock_fido_cred_make(const uint8_t rp_hash32[32],
                               uint8_t pub65[65],
                               uint8_t credid[FIDO_CREDID_LEN])
{
	if (!mock_seed_stored)
		return SE_ERR_STATE;
	uint32_t idx = mock_fido_cred_idx++;
	uint8_t priv[32];
	mock_fido_priv(rp_hash32, mock_fido_epoch, idx, priv);
	if (os_secp256r1_pubkey(priv, pub65) != 0) {
		os_secure_bzero(priv, 32);
		return SE_ERR_INTERNAL;
	}
	os_secure_bzero(priv, 32);

	credid[0] = (uint8_t)mock_fido_epoch;
	credid[1] = (uint8_t)(idx >> 24);
	credid[2] = (uint8_t)(idx >> 16);
	credid[3] = (uint8_t)(idx >> 8);
	credid[4] = (uint8_t)idx;
	mock_fido_tag(rp_hash32, mock_fido_epoch, idx, credid + 5);
	mock_nvs_save();
	return SE_OK;
}

static int mock_fido_cred_sign(const uint8_t credid[FIDO_CREDID_LEN],
                               const uint8_t rp_hash32[32],
                               const uint8_t digest32[32],
                               uint8_t sig64[64])
{
	if (!mock_seed_stored)
		return SE_ERR_STATE;
	/* User presence = the on-device confirm (fido_core A2/A3) plus, for
	 * this product, the physical Yes tap on the FIDO confirm screen — the
	 * FIDO app has NO PIN (PIN protects the wallet only). Unlike wallet
	 * signing (sign_digest, which requires a verified session) FIDO
	 * assertions are authorized by the hardware confirm alone. A real SE
	 * backend must enforce this in hardware. */
	/* credID layout (design §4.1): epoch(1B) || cred_idx(4B BE) || tag(16B) */
	uint32_t epoch = credid[0];
	uint32_t idx = ((uint32_t)credid[1] << 24) | ((uint32_t)credid[2] << 16) |
	               ((uint32_t)credid[3] << 8) | credid[4];
	if (epoch != mock_fido_epoch)
		return SE_ERR_AUTH;  /* reset (or epoch roll) invalidated this credID */

	uint8_t tag[16];
	mock_fido_tag(rp_hash32, epoch, idx, tag);
	if (!os_consttime_eq(tag, credid + 5, 16))
		return SE_ERR_AUTH;  /* tampered credID / wrong RP — never sign */
	os_secure_bzero(tag, sizeof tag);

	uint8_t priv[32];
	mock_fido_priv(rp_hash32, epoch, idx, priv);
	int rc = os_secp256r1_sign(priv, digest32, sig64);
	os_secure_bzero(priv, 32);
	if (rc != 0)
		return SE_ERR_INTERNAL;
	mock_fido_signcount++;
	mock_nvs_save();
	return SE_OK;
}

static int mock_fido_cred_exists(const uint8_t credid[FIDO_CREDID_LEN],
                                 const uint8_t rp_hash32[32])
{
	if (!mock_seed_stored)
		return SE_ERR_STATE;
	uint32_t epoch = credid[0];
	uint32_t idx = ((uint32_t)credid[1] << 24) | ((uint32_t)credid[2] << 16) |
	               ((uint32_t)credid[3] << 8) | credid[4];
	if (epoch != mock_fido_epoch)
		return SE_ERR_AUTH;  /* reset invalidated this credID */
	uint8_t tag[16];
	mock_fido_tag(rp_hash32, epoch, idx, tag);
	int ok = os_consttime_eq(tag, credid + 5, 16);
	os_secure_bzero(tag, sizeof tag);
	return ok ? SE_OK : SE_ERR_AUTH;
}

static int mock_fido_signcount_read(uint32_t *count)
{
	*count = mock_fido_signcount;
	return SE_OK;
}

/* Advance the FIDO epoch (authenticatorReset semantics, §4.4). Only FIDO
 * credentials are invalidated — the wallet seed/PIN are deliberately
 * untouched. Exposed through the se_driver_t.fido_wipe slot so the FIDO
 * app manager can wipe credentials when the FIDO app is deleted. Real SE
 * backends implement this in NVM. */
static int mock_fido_wipe(void)
{
	mock_fido_epoch++;
	mock_nvs_save();
	return SE_OK;
}

/* Test hook kept for host-side tests (tests/test_fido.c). */
void se_mock_fido_reset(void)
{
	mock_fido_wipe();
}

/* DEV-ONLY: release the session lock with no PIN. Only wired for the mock
 * backend; production SEs must leave dev_unlock NULL so the build refuses
 * to compile a no-PIN image over real hardware. */
static int mock_dev_unlock(void)
{
	mock_unlocked = true;
	return SE_OK;
}

static const se_driver_t mock_driver = {
	.name = "MOCK",
	.init = mock_init,
	.get_random = mock_get_random,
	.store_seed = mock_store_seed,
	.is_initialized = mock_is_initialized,
	.is_pin_set = mock_is_pin_set,
	.sign_digest = mock_sign_digest,
	.get_xpub = mock_get_xpub,
	.verify_pin = mock_verify_pin,
	.set_pin = mock_set_pin,
	.wipe = mock_wipe,
	.derive_session = mock_derive_session,
	.policy_authorize = mock_policy_authorize,
	.monotonic_read = mock_mono_read,
	.monotonic_increment = mock_mono_inc,
	.attest = mock_attest,
	.dev_unlock = mock_dev_unlock,
	.lock = mock_lock,
	.is_unlocked = mock_is_unlocked,
	.get_lock_timeout = mock_get_lock_timeout,
	.set_lock_timeout = mock_set_lock_timeout,
	.fido_cred_make = mock_fido_cred_make,
	.fido_cred_sign = mock_fido_cred_sign,
	.fido_cred_exists = mock_fido_cred_exists,
	.fido_signcount_read = mock_fido_signcount_read,
	.fido_wipe = mock_fido_wipe,
};

/* test helpers */
void se_mock_set_pin(const uint8_t *pin, size_t len)
{
	(void)mock_set_pin(pin, len);
}
void se_mock_reset(void)
{
	(void)mock_wipe();
}

const se_driver_t *se_active(void)
{
	return &mock_driver;
}
