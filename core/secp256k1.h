/*
 * OpenShield Hardware Wallet — secp256k1 field + point arithmetic
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Self-contained secp256k1 for pubkey derivation. 64-bit limb arithmetic
 * (5x52 or simpler: use 4x64 with __int128). NOT constant-time.
 */

#ifndef OPENSHIELD_SECP256K1_H
#define OPENSHIELD_SECP256K1_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Compressed pubkey (33 bytes) from 32-byte privkey. 0 ok, -1 invalid. */
int os_secp256k1_pubkey(const uint8_t *priv32, uint8_t *pub33);

/* Point add/double exposed for ECDSA verify later (affine, Jacobian-free). */
/* (Kept minimal for now.) */

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SECP256K1_H */
