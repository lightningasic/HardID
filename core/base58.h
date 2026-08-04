/*
 * HardID Hardware Wallet — Base58Check encoding
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#ifndef HARDID_BASE58_H
#define HARDID_BASE58_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Encode version byte + 20-byte payload as Base58Check (P2PKH/P2SH).
 * out must be >= 36 bytes. Returns length (excl NUL), or 0 on error. */
size_t os_base58check_encode(uint8_t version, const uint8_t *payload20,
                             char *out, size_t outmax);

/* Double-SHA256 helper (checksums). */
void os_sha256d(const uint8_t *data, size_t len, uint8_t *out32);

/* Generic base58check encode of an arbitrary payload (already including
 * version bytes). Returns length, or 0 on error. */
size_t os_base58_encode_check(const uint8_t *data, size_t len,
                              char *out, size_t outmax);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_BASE58_H */
