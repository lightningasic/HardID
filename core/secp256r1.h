/*
 * HardID Hardware Wallet — secp256r1 (P-256) field + point arithmetic
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Self-contained P-256 for FIDO2 ES256 (COSE alg -7). 64-bit limb
 * arithmetic (4x64 with __int128). Public keys are UNCOMPRESSED
 * (0x04 || X || Y, 65 bytes) as required by WebAuthn COSE keys.
 * NOT constant-time (see bip32.h note).
 */

#ifndef HARDID_SECP256R1_H
#define HARDID_SECP256R1_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* P-256 group order n, big-endian (RFC 6979 / FIPS 186-4). */
#define OS_SECP256R1_ORDER_NBE32 { \
	0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00, \
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, \
	0xBC,0xE6,0xFA,0xAD,0xA7,0x17,0x9E,0x84, \
	0xF3,0xB9,0xCA,0xC2,0xFC,0x63,0x25,0x51 }

/* Uncompressed public key (65 bytes, 0x04 prefix) from 32-byte privkey.
 * 0 ok, -1 invalid (priv = 0 or >= n). */
int os_secp256r1_pubkey(const uint8_t *priv32, uint8_t *pub65);

/* ---- scalar arithmetic mod n (for ECDSA) ---- */
/* r = (a * b) mod n */
void os_secp256r1_scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b);
/* r = (a + b) mod n */
void os_secp256r1_scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b);
/* r = a^(-1) mod n; returns 0 ok, -1 if a == 0 */
int os_secp256r1_scalar_inv(uint8_t *r, const uint8_t *a);

/* Parse a public key (33-byte compressed or 65-byte uncompressed) to
 * Jacobian; validates x < p and on-curve. 0 ok, -1 invalid. */
int os_secp256r1_parse_pubkey(const uint8_t *pub, size_t pub_len,
			      void *point_out);
/* Scalar multiply an arbitrary parsed point; result serialized
 * uncompressed (65 bytes). */
int os_secp256r1_point_mul(const void *point, const uint8_t *k32,
			   uint8_t *pub65);
/* Add two parsed points; result serialized uncompressed. */
int os_secp256r1_point_add(const void *a, const void *b, uint8_t *pub65);
/* Size of the opaque point object for caller allocation. */
#define OS_SECP256R1_POINT_SIZE 96

/* ---- ECDSA (RFC 6979 deterministic nonce, low-s) ---- */
/* Sign a 32-byte message hash; 64-byte compact (r||s), both big-endian.
 * Forces low-s (s <= n/2). Returns 0 on success. */
int os_secp256r1_sign(const uint8_t priv32[32], const uint8_t hash32[32],
		      uint8_t sig64[64]);
/* Verify a 64-byte compact signature against a 33/65-byte public key.
 * Returns 1 valid, 0 invalid, -1 malformed input. */
int os_secp256r1_verify(const uint8_t *pub, size_t pub_len,
			const uint8_t hash32[32], const uint8_t sig64[64]);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SECP256R1_H */
