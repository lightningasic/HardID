/*
 * OpenShield Hardware Wallet — dual-SE composite driver
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Routes se_driver_t calls to SE1 (vault: seed/keys/sign) or SE2 (guard:
 * PIN/policy/monotonic/attest). This is the production se_active() for the
 * dual-ACL16 build; se_mock.c remains for host tests.
 */

#include "../core/se_driver.h"
#include "se_transport.h"
#include "se_acl16.h"
#include <string.h>

static se_acl16_t g_se1, g_se2;

static int comp_init(void)
{
	const se_transport_t *t = se_transport_get();
	if (!t || !t->init)
		return SE_ERR_COMM;
	if (t->init() != SE_T_OK)
		return SE_ERR_COMM;
	se_acl16_init_ctx(&g_se1, SE_CS_1);
	se_acl16_init_ctx(&g_se2, SE_CS_2);
	return SE_OK;
}

static int comp_get_random(uint8_t *buf, size_t len)
{
	return se_acl16_get_random(&g_se1, buf, len) == 0 ? SE_OK : SE_ERR_INTERNAL;
}

static int comp_store_seed(const uint8_t *seed32)
{
	return se_acl16_store_seed(&g_se1, seed32) == 0 ? SE_OK : SE_ERR_INTERNAL;
}

static int comp_is_initialized(bool *init)
{
	return se_acl16_is_initialized(&g_se1, init) == 0 ? SE_OK : SE_ERR_INTERNAL;
}

static int comp_sign_digest(const uint32_t *path, size_t path_len,
                            const uint8_t *digest32, uint8_t *sig64, uint8_t *recid)
{
	return se_acl16_sign_digest(&g_se1, path, path_len, digest32, sig64, recid);
}

static int comp_get_xpub(const uint32_t *path, size_t path_len,
                         char *xpub_out, size_t xpub_max)
{
	return se_acl16_get_xpub(&g_se1, path, path_len, xpub_out, xpub_max);
}

static int comp_verify_pin(const uint8_t *pin, size_t len,
                           uint32_t *wait_seconds, bool *is_duress)
{
	return se_acl16_verify_pin(&g_se2, pin, len, wait_seconds, is_duress);
}

static int comp_policy_authorize(uint32_t policy_id, uint64_t amount)
{
	return se_acl16_policy_authorize(&g_se2, policy_id, amount);
}

static int comp_monotonic_read(uint32_t *counter)
{
	return se_acl16_monotonic_read(&g_se2, counter) == 0 ? SE_OK : SE_ERR_INTERNAL;
}

static int comp_monotonic_increment(void)
{
	return se_acl16_monotonic_increment(&g_se2) == 0 ? SE_OK : SE_ERR_INTERNAL;
}

static int comp_attest(const uint8_t *challenge32, uint8_t *response, size_t *resp_len)
{
	return se_acl16_attest(&g_se2, challenge32, response, resp_len);
}

static const se_driver_t composite_driver = {
	.name = "DUAL-ACL16",
	.init = comp_init,
	.get_random = comp_get_random,
	.store_seed = comp_store_seed,
	.is_initialized = comp_is_initialized,
	.sign_digest = comp_sign_digest,
	.get_xpub = comp_get_xpub,
	.verify_pin = comp_verify_pin,
	.policy_authorize = comp_policy_authorize,
	.monotonic_read = comp_monotonic_read,
	.monotonic_increment = comp_monotonic_increment,
	.attest = comp_attest,
};

/* Dual-source TRNG hooks for seed.c: SE1 and SE2 each contribute. */
int os_seed_se_trng(uint8_t *buf, size_t len)
{
	return se_acl16_get_random(&g_se1, buf, len);
}
int os_seed_se2_trng(uint8_t *buf, size_t len)
{
	return se_acl16_get_random(&g_se2, buf, len);
}

const se_driver_t *se_active(void)
{
	return &composite_driver;
}
