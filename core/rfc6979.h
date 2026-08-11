/*
 * HardID Hardware Wallet — RFC6979 deterministic nonce (ECDSA)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * RFC 6979 §3.2 HMAC-SHA256 based deterministic k generation. Deterministic
 * nonces eliminate the catastrophic RNG-failure key-leak class (and the
 * kleptographic covert-channel concern when combined with a verifiable
 * nonce commitment).
 */

#ifndef HARDID_RFC6979_H
#define HARDID_RFC6979_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Generate deterministic nonce k (1..n-1) from a 32-byte private key and
 * 32-byte message hash, using group order n (32-byte big-endian).
 * retry skips candidates (RFC 6979 §3.2 step h loop); pass 0 for the first.
 * Returns 0 on success. */
int os_rfc6979_nonce_n(const uint8_t order_nbe32[32],
		       const uint8_t priv32[32], const uint8_t hash32[32],
		       int retry, uint8_t k_out32[32]);

/* Convenience wrapper for secp256k1 (group order n hardcoded). */
int os_rfc6979_nonce(const uint8_t priv32[32], const uint8_t hash32[32],
                     int retry, uint8_t k_out32[32]);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_RFC6979_H */
