/*
 * OpenShield Hardware Wallet — secure memory zeroization
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * memset can be optimized away by the compiler when the buffer is dead
 * after the call. os_secure_bzero uses a volatile function pointer so the
 * call is never elided — key material must not linger in RAM.
 */

#ifndef OPENSHIELD_SECURE_ZERO_H
#define OPENSHIELD_SECURE_ZERO_H

#include <stddef.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

static void *(*volatile os_secure_bzero_vp)(void *, int, size_t) = memset;

static inline void os_secure_bzero(void *ptr, size_t len)
{
	os_secure_bzero_vp(ptr, 0, len);
}

/* Constant-time equality: returns 1 if a[0..len) == b[0..len), else 0.
 * No early exit — comparison time does not leak the mismatch position. */
static inline int os_consttime_eq(const void *a, const void *b, size_t len)
{
	const unsigned char *pa = (const unsigned char *)a;
	const unsigned char *pb = (const unsigned char *)b;
	unsigned char diff = 0;
	for (size_t i = 0; i < len; i++)
		diff |= (unsigned char)(pa[i] ^ pb[i]);
	return diff == 0;
}

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SECURE_ZERO_H */
