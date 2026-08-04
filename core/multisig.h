/*
 * HardID Hardware Wallet — multisig (M-of-N) configuration
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Holds an M-of-N cosigner set and validates its integrity. The critical
 * security property is enforced by the UI flow (each signer independently
 * confirms the SAME parsed intent on their own device); this module only
 * manages configuration and partial-signature accounting.
 */

#ifndef HARDID_MULTISIG_H
#define HARDID_MULTISIG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_MS_MAX_COSIGNERS 15

typedef enum {
	OS_MS_P2SH,
	OS_MS_P2WSH,
	OS_MS_TAPROOT,
} os_ms_script;

typedef struct {
	uint8_t threshold_m;
	uint8_t total_n;
	os_ms_script script;
	/* xpub fingerprints (4 bytes each) to identify cosigners compactly */
	uint8_t cosigner_fp[OS_MS_MAX_COSIGNERS][4];
	/* this device's own index in the set, or 0xFF if not a member */
	uint8_t self_index;
} os_multisig;

/* Validate configuration: 1 <= M <= N <= OS_MS_MAX_COSIGNERS, unique fps.
 * Returns 0 on success, -1 on invalid. */
int os_ms_validate(const os_multisig *m);

/* Record a partial signature by cosigner fingerprint.
 * seen[] tracks which indices have signed. Returns the cosigner index that
 * signed, or 0xFF if fp is NOT in the set (unknown cosigner — the caller
 * should surface this, not silently accept it). Use os_ms_quorum to check
 * whether enough distinct cosigners have signed. */
uint8_t os_ms_record_sig(const os_multisig *m, const uint8_t fp[4],
                         bool seen[OS_MS_MAX_COSIGNERS]);

/* True when at least M distinct cosigners have signed. */
bool os_ms_quorum(const os_multisig *m, const bool seen[OS_MS_MAX_COSIGNERS]);

/* Locate a cosigner index by fingerprint, or 0xFF if not present. */
uint8_t os_ms_find(const os_multisig *m, const uint8_t fp[4]);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_MULTISIG_H */
