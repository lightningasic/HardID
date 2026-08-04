/*
 * HardID Hardware Wallet — HKDF-SHA256 (RFC 5869)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Used for multi-source entropy mixing at seed generation:
 *   PRK = HMAC-SHA256(salt, IKM)
 *   OKM = HMAC-SHA256(PRK, info || 0x01)   (single 32-byte block)
 */

#ifndef HARDID_HKDF_H
#define HARDID_HKDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_HKDF_SHA256_LEN 32

/* One-shot HKDF-SHA256 extract+expand for a single 32-byte output block.
 * ikm may be assembled by the caller from multiple entropy sources. */
void os_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out32);

/* Streaming HMAC-SHA256 for multi-part messages (e.g. multi-source IKM).
 * The context stores both pad states, so final produces a correct HMAC.
 * Opaque to callers; definition lives in hkdf.c. */
typedef struct os_hmac_sha256_ctx os_hmac_sha256_ctx;

/* Static storage for the context (embedded, no dynamic alloc). */
#define OS_HMAC_SHA256_CTX_SIZE (2 * (8*4 + 8 + 64 + sizeof(size_t) + 8))

/* Caller-provided storage wrapper. */
typedef struct {
	unsigned char _opaque[OS_HMAC_SHA256_CTX_SIZE];
} os_hmac_sha256_ctx_storage;

void os_hmac_sha256_init(os_hmac_sha256_ctx_storage *ctx,
                         const uint8_t *key, size_t key_len);
void os_hmac_sha256_update(os_hmac_sha256_ctx_storage *ctx,
                           const uint8_t *data, size_t len);
void os_hmac_sha256_final(os_hmac_sha256_ctx_storage *ctx, uint8_t *out32);

/* one-shot convenience */
void os_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len, uint8_t *out32);

/* Expand a PRK into a single 32-byte block: HMAC(PRK, info || 0x01). */
void os_hkdf_expand32(const uint8_t *prk32,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out32);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_HKDF_H */
