/*
 * OpenShield Hardware Wallet — Keccak-256 (Ethereum variant)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation of the Keccak-f[1600] permutation.
 * Not derived from TREZOR code. License: Apache License 2.0
 *
 * NOTE: This is Keccak-256 (Ethereum, padding 0x01), NOT SHA3-256
 * (padding 0x06). Ethereum uses the original Keccak padding.
 */

#ifndef OPENSHIELD_KECCAK_H
#define OPENSHIELD_KECCAK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_KECCAK256_LEN 32

typedef struct {
	uint64_t state[25];       /* 1600-bit state, 5x5 lanes */
	uint8_t  buffer[136];     /* rate = 1088 bits = 136 bytes for 256-bit */
	size_t   buffer_len;
} os_keccak_ctx;

void os_keccak256_init(os_keccak_ctx *ctx);
void os_keccak256_update(os_keccak_ctx *ctx, const uint8_t *data, size_t len);
void os_keccak256_final(os_keccak_ctx *ctx, uint8_t *out32);

/* one-shot convenience */
void os_keccak256(const uint8_t *data, size_t len, uint8_t *out32);

/* Ethereum address checksum (EIP-55): writes 42-char "0x.." mixed-case
 * address into out (must be >= 43 bytes). */
void os_eth_address_checksum(const uint8_t addr20[20], char *out43);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_KECCAK_H */
