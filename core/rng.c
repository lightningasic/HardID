/*
 * HardID Hardware Wallet — RNG core (portable)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "rng.h"

/* Poll iterations before declaring a timeout. */
#define OS_RNG_POLL_TIMEOUT   100000u
/* Recovery attempts (flag clear + block reset) before giving up. */
#define OS_RNG_MAX_RECOVERY   8
/* Max consecutive duplicate outputs tolerated (continuous test). */
#define OS_RNG_MAX_DUPLICATES 4
/* Startup self-test sample count. */
#define OS_RNG_SELF_TEST_N    8

/* Weak default: halt with interrupts masked. Firmware overrides to show an
 * on-screen error first. Host tests define OS_RNG_NO_DEFAULT_FATAL and
 * provide their own. */
#ifndef OS_RNG_NO_DEFAULT_FATAL
__attribute__((weak, noreturn)) void os_rng_fatal(void)
{
	for (;;) { /* halt */ }
}
#endif

/* Returns 1 and stores a word, or 0 if the source stayed unhealthy. */
static int read_hw(uint32_t *out)
{
	uint32_t wait;
	int recovery;

	for (recovery = 0; recovery < OS_RNG_MAX_RECOVERY; recovery++) {
		for (wait = 0; wait < OS_RNG_POLL_TIMEOUT; wait++) {
			uint32_t sr = os_rng_hw_read_status();
			if (sr & 0x2u) { /* error flag pending (platform-defined bit) */
				os_rng_hw_recover();
				break;
			}
			if (sr & 0x1u) { /* data ready */
				*out = os_rng_hw_read_data();
				return 1;
			}
		}
	}
	return 0;
}

uint32_t os_rng_u32(void)
{
	static uint32_t last;
	static int have_last;
	uint32_t new = 0;
	int dup;

	for (dup = 0; dup < OS_RNG_MAX_DUPLICATES; dup++) {
		if (!read_hw(&new))
			os_rng_fatal();
		if (!have_last || new != last) {
			last = new;
			have_last = 1;
			return new;
		}
	}
	os_rng_fatal();
}

void os_rng_fill(uint8_t *buf, size_t len)
{
	size_t i;
	uint32_t r = 0;
	for (i = 0; i < len; i++) {
		if (i % 4 == 0)
			r = os_rng_u32();
		buf[i] = (uint8_t)(r >> ((i % 4) * 8));
	}
}

uint32_t os_rng_uniform(uint32_t n)
{
	if (n == 0)
		return 0;              /* undefined range: no valid draw, return 0 */
	uint32_t x, max = 0xFFFFFFFFu - (0xFFFFFFFFu % n);
	while ((x = os_rng_u32()) >= max)
		;
	return x / (max / n);
}

void os_rng_shuffle(char *buf, size_t len)
{
	if (len < 2)
		return;                  /* nothing to shuffle */
	size_t i;
	for (i = len - 1; i >= 1; i--) {
		uint32_t j = os_rng_uniform((uint32_t)i + 1);
		char t = buf[j];
		buf[j] = buf[i];
		buf[i] = t;
	}
}

int os_rng_self_test(void)
{
	uint32_t s[OS_RNG_SELF_TEST_N];
	uint32_t any_or = 0, any_and = 0xFFFFFFFFu;
	int i, all_same = 1;

	for (i = 0; i < OS_RNG_SELF_TEST_N; i++) {
		if (!read_hw(&s[i]))
			return -1;
		any_or |= s[i];
		any_and &= s[i];
		if (i > 0 && s[i] != s[0])
			all_same = 0;
	}
	if (all_same)
		return -1;               /* stuck output */
	if (any_or == 0 || any_and == 0xFFFFFFFFu)
		return -1;               /* stuck-at 0 / 1 */
	return 0;
}
