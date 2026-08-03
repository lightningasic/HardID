/*
 * OpenShield Hardware Wallet — RNG subsystem
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0 (see LICENSE in repository root)
 *
 * Hardened STM32 TRNG driver:
 *  - bounded polling, RM0090 error-flag recovery
 *  - startup health self-test (stuck-at / repeated-output)
 *  - fail-safe escalation (weak, overridable) instead of silent hang
 */

#ifndef OPENSHIELD_RNG_H
#define OPENSHIELD_RNG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Fill buf with len bytes of hardware TRNG output. Halts via os_rng_fatal
 * if the entropy source is unhealthy. */
void os_rng_fill(uint8_t *buf, size_t len);

/* Single 32-bit word from the TRNG. */
uint32_t os_rng_u32(void);

/* Uniform value in [0, n) via rejection sampling (no modulo bias). */
uint32_t os_rng_uniform(uint32_t n);

/* Fisher-Yates shuffle of buf[0..len). */
void os_rng_shuffle(char *buf, size_t len);

/* Startup health test: 0 = healthy, -1 = do not generate keys. */
int os_rng_self_test(void);

/* Fail-safe halt on unrecoverable TRNG failure. Weak; override to display
 * an on-screen error before halting. Never returns. */
void os_rng_fatal(void) __attribute__((noreturn));

/* Platform hooks (implement per board; a default STM32F2/F4 backend is
 * provided in rng_stm32.c). */
uint32_t os_rng_hw_read_status(void);
uint32_t os_rng_hw_read_data(void);
void     os_rng_hw_recover(void);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_RNG_H */
