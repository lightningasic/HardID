/*
 * HardID Hardware Wallet — unconditional entropy pool
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Absorbs raw bytes from many weak physical entropy sources (touch jitter,
 * ADC noise, bus timing, RTC drift) and mixes them with SHA-256 so that the
 * output is statistically independent of any attacker-predictable input, as
 * long as at least one source contributes >= 1 bit of true randomness.
 *
 * Each absorb() domain-separates by length, so the mixture is prefix-safe:
 * a trailing source cannot extend an earlier one into a colliding input.
 * Extract() is a single-shot finalization over the pool state. All internal
 * state is wiped on extract() so a caller cannot double-draw the same
 * material.
 */

#ifndef HARDID_PHYS_ENTROPY_H
#define HARDID_PHYS_ENTROPY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_PHYS_POOL_LEN 32

typedef struct {
	uint8_t st[OS_PHYS_POOL_LEN];
	int     used;
} os_phys_pool_t;

/* Initialize a fresh pool (all-zero state + length tag). */
void os_phys_pool_init(os_phys_pool_t *p);

/* Absorb len raw bytes into the pool: st = SHA256(0x01 || st || len_be32 || data). */
void os_phys_pool_absorb(os_phys_pool_t *p, const uint8_t *data, size_t len);

/* Finalize: out = first min(out_len, 32) bytes of the mixed pool state
 * (SHA256(0x02 || st || out_len_be32)), any remaining bytes zeroed, pool
 * state wiped. Single-use: a second call yields zeros. */
void os_phys_pool_extract(os_phys_pool_t *p, uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_PHYS_ENTROPY_H */
