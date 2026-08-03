/*
 * OpenShield Hardware Wallet — ECDSA (secp256k1) sign & verify
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Sign uses RFC 6979 deterministic nonces. Verify uses Jacobian point math.
 * NOTE: reference implementation for host/emulator and signature VERIFY on
 * device. On-device SIGNING must use the SE's hardware ECDSA — the scalar
 * inverse and scalar multiplication here are NOT constant-time and are
 * side-channel unsafe for live private keys on an MCU. Verification and
 * public-key derivation are safe to use anywhere.
 */

#ifndef OPENSHIELD_ECDSA_H
#define OPENSHIELD_ECDSA_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sign a 32-byte message hash with a 32-byte private key.
 * Produces 64-byte compact signature (r || s), both 32-byte big-endian.
 * Forces low-s (BIP-62 / EIP-2). Returns 0 on success. */
int os_ecdsa_sign(const uint8_t priv32[32], const uint8_t hash32[32],
                  uint8_t sig64[64]);

/* Verify a 64-byte compact signature against a 33-byte compressed pubkey.
 * Returns 1 if valid, 0 if invalid, -1 on malformed input. */
int os_ecdsa_verify(const uint8_t pub33[33], const uint8_t hash32[32],
                    const uint8_t sig64[64]);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_ECDSA_H */
