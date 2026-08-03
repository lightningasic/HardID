/*
 * OpenShield Hardware Wallet — SHA-512 / HMAC-SHA512 / PBKDF2
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#ifndef OPENSHIELD_SHA512_H
#define OPENSHIELD_SHA512_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_SHA512_LEN 64

typedef struct {
	uint64_t state[8];
	uint64_t bitlen_lo, bitlen_hi;
	uint8_t  buffer[128];
	size_t   buffer_len;
} os_sha512_ctx;

void os_sha512_init(os_sha512_ctx *ctx);
void os_sha512_update(os_sha512_ctx *ctx, const uint8_t *data, size_t len);
void os_sha512_final(os_sha512_ctx *ctx, uint8_t *out64);
void os_sha512(const uint8_t *data, size_t len, uint8_t *out64);

/* HMAC-SHA512 context storing both pad states. */
typedef struct {
	unsigned char _opaque[2 * (8*8 + 16 + 128 + sizeof(size_t) + 16)];
} os_hmac_sha512_ctx;

void os_hmac_sha512_init(os_hmac_sha512_ctx *ctx, const uint8_t *key, size_t klen);
void os_hmac_sha512_update(os_hmac_sha512_ctx *ctx, const uint8_t *data, size_t len);
void os_hmac_sha512_final(os_hmac_sha512_ctx *ctx, uint8_t *out64);
void os_hmac_sha512(const uint8_t *key, size_t klen,
                    const uint8_t *data, size_t len, uint8_t *out64);

/* PBKDF2-HMAC-SHA512 (used by BIP39 seed derivation). */
void os_pbkdf2_sha512(const uint8_t *password, size_t plen,
                      const uint8_t *salt, size_t slen,
                      uint32_t iterations, uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SHA512_H */
