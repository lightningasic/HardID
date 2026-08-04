/*
 * OpenShield Hardware Wallet — seed generation (multi-source entropy)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Combines entropy from independent sources via HKDF-SHA256 so that no
 * single compromised/failed source can determine the seed:
 *   IKM = se1_trng(32) || se2_trng(32) || host_entropy(len)
 *   PRK = HMAC(salt="OpenShield seed v1", IKM)
 *   seed = HMAC(PRK, "mnemonic" || 0x01)
 *
 * Dual-SE hardware (two ACL16): two independent EAL6+ TRNGs + host entropy.
 * The main-controller TRNG is OUT of the trust chain. For single-SE builds
 * a second source may come from the MCU TRNG instead (legacy fallback).
 */

#ifndef OPENSHIELD_SEED_H
#define OPENSHIELD_SEED_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_SEED_LEN 32

/* Platform hook: read len bytes from the secure element's TRNG. */
int os_seed_se_trng(uint8_t *buf, size_t len);

/* Platform hook (dual-SE builds): read len bytes from the SECOND SE's TRNG.
 * Default falls back to the main-controller TRNG when not overridden. */
int os_seed_se2_trng(uint8_t *buf, size_t len);

/* Generate a 32-byte seed from the three entropy sources.
 * host_entropy may be NULL (len 0). Returns 0 on success, -1 if any
 * hardware source failed. The seed buffer must be zeroized by the caller
 * after use. */
int os_seed_generate(const uint8_t *host_entropy, size_t host_len,
                     uint8_t *seed_out32);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SEED_H */
