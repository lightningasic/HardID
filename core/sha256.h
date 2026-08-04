/*
 * HardID Hardware Wallet — SHA-256 (public interface)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * The SHA-256 core lives in hkdf.c; this header exposes a one-shot helper
 * for modules that need plain SHA-256 (BIP39 checksum, base58check, ...).
 */

#ifndef HARDID_SHA256_H
#define HARDID_SHA256_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_SHA256_LEN 32

void os_sha256(const uint8_t *data, size_t len, uint8_t *out32);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SHA256_H */
