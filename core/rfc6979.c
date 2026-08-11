/*
 * HardID Hardware Wallet — RFC6979 deterministic nonce (ECDSA)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "rfc6979.h"
#include "hkdf.h"
#include "secure_zero.h"
#include <string.h>

/*
 * SECP256K1_ORDER and P256_ORDER: 32-byte big-endian group orders of the
 * two supported curves. RFC 6979 defines bits2octets / k range against q
 * (the group order), so the ordering constant is a parameter, not a global.
 */
static const uint8_t SECP256K1_ORDER[32] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
	0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};

/* bits2octets: take hash mod n as RFC 6979 requires (here hash is 32 bytes,
 * qlen=256 = hlen, so it is a conditional subtract). */
static void bits2octets(const uint8_t *nbe, const uint8_t *h, uint8_t *out)
{
	memcpy(out, h, 32);
	/* if out >= n, subtract n (once is enough: out < 2^256 < 2n) */
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (out[i] != nbe[i]) { ge = out[i] > nbe[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = out[i] - nbe[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			out[i] = (uint8_t)d;
		}
	}
}

static int k_is_valid(const uint8_t *nbe, const uint8_t *k)
{
	/* 1 <= k <= n-1 */
	int nonzero = 0, lt = 0;
	for (int i = 0; i < 32; i++) {
		if (k[i]) nonzero = 1;
		if (k[i] != nbe[i]) { lt = k[i] < nbe[i]; break; }
		if (i == 31) lt = 0; /* equal => invalid */
	}
	return nonzero && lt;
}

int os_rfc6979_nonce_n(const uint8_t order_nbe32[32],
		       const uint8_t priv32[32], const uint8_t hash32[32],
		       int retry, uint8_t k_out32[32])
{
	const uint8_t *nbe = order_nbe32;
	uint8_t V[32], K[32], bx[64];
	os_hmac_sha256_ctx_storage h;

	memset(V, 0x01, 32);
	memset(K, 0x00, 32);

	/* bx = int2octets(priv) || bits2octets(hash) */
	memcpy(bx, priv32, 32);
	bits2octets(nbe, hash32, bx + 32);

	/* K = HMAC(K, V || 0x00 || bx) */
	os_hmac_sha256_init(&h, K, 32);
	os_hmac_sha256_update(&h, V, 32);
	{ uint8_t z = 0x00; os_hmac_sha256_update(&h, &z, 1); }
	os_hmac_sha256_update(&h, bx, 64);
	os_hmac_sha256_final(&h, K);

	/* V = HMAC(K, V) */
	os_hmac_sha256(K, 32, V, 32, V);

	/* K = HMAC(K, V || 0x01 || bx) */
	os_hmac_sha256_init(&h, K, 32);
	os_hmac_sha256_update(&h, V, 32);
	{ uint8_t o = 0x01; os_hmac_sha256_update(&h, &o, 1); }
	os_hmac_sha256_update(&h, bx, 64);
	os_hmac_sha256_final(&h, K);

	/* V = HMAC(K, V) */
	os_hmac_sha256(K, 32, V, 32, V);

	for (;;) {
		/* V = HMAC(K, V); candidate = V */
		os_hmac_sha256(K, 32, V, 32, V);
		if (k_is_valid(nbe, V)) {
			if (retry == 0) {
				memcpy(k_out32, V, 32);
				os_secure_bzero(K, 32);
				os_secure_bzero(V, 32);
				os_secure_bzero(bx, 64);
				return 0;
			}
			retry--;
		}
		/* K = HMAC(K, V || 0x00); V = HMAC(K, V) */
		os_hmac_sha256_init(&h, K, 32);
		os_hmac_sha256_update(&h, V, 32);
		{ uint8_t z = 0x00; os_hmac_sha256_update(&h, &z, 1); }
		os_hmac_sha256_final(&h, K);
		os_hmac_sha256(K, 32, V, 32, V);
	}
}

int os_rfc6979_nonce(const uint8_t priv32[32], const uint8_t hash32[32],
                     int retry, uint8_t k_out32[32])
{
	return os_rfc6979_nonce_n(SECP256K1_ORDER, priv32, hash32,
	                           retry, k_out32);
}
