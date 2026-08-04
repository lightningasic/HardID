/*
 * HardID Hardware Wallet — secp256k1 field + point arithmetic
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Self-contained secp256k1 for pubkey derivation. 64-bit limb arithmetic
 * (5x52 or simpler: use 4x64 with __int128). NOT constant-time.
 */

#ifndef HARDID_SECP256K1_H
#define HARDID_SECP256K1_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compressed pubkey (33 bytes) from 32-byte privkey. 0 ok, -1 invalid. */
int os_secp256k1_pubkey(const uint8_t *priv32, uint8_t *pub33);

/* ---- scalar arithmetic mod n (for ECDSA) ---- */
/* r = (a * b) mod n */
void os_secp256k1_scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b);
/* r = (a + b) mod n */
void os_secp256k1_scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b);
/* r = a^(-1) mod n; returns 0 ok, -1 if a == 0 */
int os_secp256k1_scalar_inv(uint8_t *r, const uint8_t *a);

/* Decompress a 33-byte pubkey to Jacobian; returns 0 ok, -1 if invalid. */
int os_secp256k1_parse_pubkey(const uint8_t *pub33, void *point_out);
/* Scalar multiply an arbitrary parsed point; result serialized compressed. */
int os_secp256k1_point_mul(const void *point, const uint8_t *k32, uint8_t *pub33);
/* Add two parsed points; result serialized compressed. */
int os_secp256k1_point_add(const void *a, const void *b, uint8_t *pub33);
/* Size of the opaque point object for caller allocation. */
#define OS_SECP256K1_POINT_SIZE 96

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SECP256K1_H */
