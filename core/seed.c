/*
 * OpenShield Hardware Wallet — seed generation (multi-source entropy)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "seed.h"
#include "rng.h"
#include "hkdf.h"
#include "secure_zero.h"
#include <string.h>

/* Weak default: a platform MUST override this to read the SE's TRNG.
 * Default fails closed (seed generation refuses to run without SE entropy),
 * so linking core/ alone never silently produces a single-source seed.
 * Tests providing their own implementation define OS_SEED_NO_DEFAULT_HOOK. */
#ifndef OS_SEED_NO_DEFAULT_HOOK
__attribute__((weak)) int os_seed_se_trng(uint8_t *buf, size_t len)
{
	(void)buf; (void)len;
	return -1;
}
#endif

int os_seed_generate(const uint8_t *host_entropy, size_t host_len,
                     uint8_t *seed_out32)
{
	static const uint8_t salt[] = "OpenShield seed v1";
	static const uint8_t info[] = "mnemonic";
	uint8_t se[OS_SEED_LEN], mcu[OS_SEED_LEN];
	uint8_t prk[32];
	os_hmac_sha256_ctx_storage h;

	if (os_seed_se_trng(se, sizeof se) != 0) {
		/* wipe any partially-filled entropy before bailing out */
		os_secure_bzero(se, sizeof se);
		os_secure_bzero(mcu, sizeof mcu);
		os_secure_bzero(prk, sizeof prk);
		return -1;
	}
	os_rng_fill(mcu, sizeof mcu);

	/* Extract: PRK = HMAC(salt, se || mcu || host) */
	os_hmac_sha256_init(&h, salt, sizeof(salt) - 1);
	os_hmac_sha256_update(&h, se, sizeof se);
	os_hmac_sha256_update(&h, mcu, sizeof mcu);
	if (host_entropy && host_len > 0)
		os_hmac_sha256_update(&h, host_entropy, host_len);
	os_hmac_sha256_final(&h, prk);

	/* Expand (single 32-byte block) */
	os_hkdf_expand32(prk, info, sizeof(info) - 1, seed_out32);

	os_secure_bzero(se, sizeof se);
	os_secure_bzero(mcu, sizeof mcu);
	os_secure_bzero(prk, sizeof prk);
	return 0;
}
