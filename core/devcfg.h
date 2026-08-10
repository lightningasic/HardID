/*
 * HardID Hardware Wallet — development build configuration
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * DEV-ONLY compile switches. Nothing in here may ship in production; the
 * production configuration always returns the safe default.
 */

#ifndef HARDID_DEVCFG_H
#define HARDID_DEVCFG_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True when this build disables all PIN prompts and PIN gating (bring-up
 * only; real devices must return false). Defined by Kconfig on ESP-IDF;
 * host tests and production builds leave it off. */
#if defined(CONFIG_HARDID_DEV_NO_PIN)
#define HARDID_DEV_NO_PIN 1
#else
#define HARDID_DEV_NO_PIN 0
#endif

static inline bool os_dev_no_pin_enabled(void)
{
	return HARDID_DEV_NO_PIN != 0;
}

/* DEV-ONLY: 4-word test seeds (no BIP39 checksum, 44-bit). See Kconfig
 * HARDID_DEV_TEST_SEED. Production builds leave this off. */
#if defined(CONFIG_HARDID_DEV_TEST_SEED)
#define HARDID_DEV_TEST_SEED 1
#else
#define HARDID_DEV_TEST_SEED 0
#endif

static inline bool os_dev_test_seed_enabled(void)
{
	return HARDID_DEV_TEST_SEED != 0;
}

#ifdef __cplusplus
}
#endif

#endif /* HARDID_DEVCFG_H */