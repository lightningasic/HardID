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

static int mock_init(void) { return SE_OK; }

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
	mock_pin_len = 0;
	mock_unlocked = false;
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
