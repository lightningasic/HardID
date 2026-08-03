/*
 * OpenShield Hardware Wallet — ECDSA (secp256k1) sign & verify
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "ecdsa.h"
#include "secp256k1.h"
#include "rfc6979.h"
#include "secure_zero.h"
#include <string.h>

static const uint8_t EC_NBE[32] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
	0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint8_t HALF_N[32] = {  /* n/2 (floor) */
	0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

/* z = hash mod n (hash is 32 bytes; conditional subtract once) */
static void hash_to_scalar(const uint8_t *hash32, uint8_t *out)
{
	memcpy(out, hash32, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (out[i] != EC_NBE[i]) { ge = out[i] > EC_NBE[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = out[i] - EC_NBE[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			out[i] = (uint8_t)d;
		}
	}
}

/* r = x-of-(k*G) mod n: take compressed pubkey, strip prefix, reduce x */
static int nonce_point_rx(const uint8_t *k32, uint8_t *rx32)
{
	uint8_t pub[33];
	if (os_secp256k1_pubkey(k32, pub) != 0)
		return -1;
	/* x is bytes 1..32; n < 2^256 so x mod n = conditional subtract */
	memcpy(rx32, pub + 1, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (rx32[i] != EC_NBE[i]) { ge = rx32[i] > EC_NBE[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = rx32[i] - EC_NBE[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			rx32[i] = (uint8_t)d;
		}
	}
	return 0;
}

static int is_zero(const uint8_t *a)
{
	for (int i = 0; i < 32; i++) if (a[i]) return 0;
	return 1;
}

int os_ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32],
                  uint8_t sig64[64])
{
	uint8_t z[32], k[32], r[32], s[32], tmp[32];
	int retry = 0;

	hash_to_scalar(hash32, z);

	for (;;) {
		if (os_rfc6979_nonce(priv32, hash32, retry, k) != 0)
			return -1;
		if (nonce_point_rx(k, r) != 0 || is_zero(r)) {
			retry++;
			continue;
		}
		/* s = k^-1 * (z + r*priv) mod n */
		os_secp256k1_scalar_mul(tmp, r, priv32);
		os_secp256k1_scalar_add(tmp, tmp, z);
		if (os_secp256k1_scalar_inv(k, k) != 0)
			return -1;
		os_secp256k1_scalar_mul(s, k, tmp);
		if (is_zero(s)) {
			retry++;
			continue;
		}
		break;
	}

	/* low-s normalization */
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (s[i] != HALF_N[i]) { ge = s[i] > HALF_N[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = EC_NBE[i] - s[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			s[i] = (uint8_t)d;
		}
	}

	memcpy(sig64, r, 32);
	memcpy(sig64 + 32, s, 32);
	os_secure_bzero(z, 32);
	os_secure_bzero(k, 32);
	os_secure_bzero(tmp, 32);
	os_secure_bzero(s, 32);
	return 0;
}

int os_ecdsa_verify(const uint8_t pub33[33], const uint8_t hash32[32],
                    const uint8_t sig64[64])
{
	const uint8_t *r = sig64, *s = sig64 + 32;
	uint8_t z[32], w[32], u1[32], u2[32], tmp[32];
	uint8_t pt_buf[OS_SECP256K1_POINT_SIZE];
	uint8_t p1[33], p2[33];

	/* reject zero / >= n for r and s */
	for (int half = 0; half < 2; half++) {
		const uint8_t *v = sig64 + half * 32;
		int nonzero = 0, lt = 0;
		for (int i = 0; i < 32; i++) {
			if (v[i]) nonzero = 1;
			if (v[i] != EC_NBE[i]) { lt = v[i] < EC_NBE[i]; break; }
			if (i == 31) lt = 0;
		}
		if (!nonzero || !lt)
			return -1;
	}

	if (os_secp256k1_parse_pubkey(pub33, pt_buf) != 0)
		return -1;

	hash_to_scalar(hash32, z);
	/* w = s^-1, u1 = z*w, u2 = r*w */
	if (os_secp256k1_scalar_inv(w, s) != 0)
		return -1;
	os_secp256k1_scalar_mul(u1, z, w);
	os_secp256k1_scalar_mul(u2, r, w);

	/* P = u1*G + u2*pub */
	if (os_secp256k1_pubkey(u1, p1) != 0)
		return 0;
	if (os_secp256k1_point_mul(pt_buf, u2, p2) != 0)
		return 0;
	/* add the two points: parse p1, add p2 as raw */
	uint8_t a_buf[OS_SECP256K1_POINT_SIZE], b_buf[OS_SECP256K1_POINT_SIZE];
	uint8_t px[33];
	if (os_secp256k1_parse_pubkey(p1, a_buf) != 0)
		return -1;
	if (os_secp256k1_parse_pubkey(p2, b_buf) != 0)
		return -1;
	if (os_secp256k1_point_add(a_buf, b_buf, px) != 0)
		return 0;

	/* valid if (x of P) mod n == r */
	memcpy(tmp, px + 1, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (tmp[i] != EC_NBE[i]) { ge = tmp[i] > EC_NBE[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = tmp[i] - EC_NBE[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			tmp[i] = (uint8_t)d;
		}
	}
	int valid = os_consttime_eq(tmp, r, 32) ? 1 : 0;
	os_secure_bzero(z, 32);
	os_secure_bzero(w, 32);
	os_secure_bzero(u1, 32);
	os_secure_bzero(u2, 32);
	os_secure_bzero(tmp, 32);
	return valid;
}
