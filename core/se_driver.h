/*
 * HardID Hardware Wallet — Secure Element driver abstraction
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * The SE is the root of trust: seed/private keys, PIN state, SignPolicy
 * counters, and the anti-rollback monotonic counter all live inside it and
 * never leave. The MCU is assumed compromisable. This interface lets the
 * vendor-specific backend (ACL16 / THD89 / eSE) be swapped without touching
 * upper layers. All buffers for key material are written BY the SE only.
 */

#ifndef HARDID_SE_H
#define HARDID_SE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define SE_OK            0
#define SE_ERR_COMM     -1   /* transport failure */
#define SE_ERR_AUTH     -2   /* PIN wrong / not verified */
#define SE_ERR_LOCKED   -3   /* backoff in effect */
#define SE_ERR_PARAM    -4
#define SE_ERR_STATE    -5   /* e.g. already provisioned */
#define SE_ERR_INTERNAL -6

typedef struct se_driver {
	const char *name;         /* "ACL16", "THD89", ... */

	/* Probe + init the transport (SPI/I2C/ISO7816). SE_OK if present. */
	int (*init)(void);

	/* Read len bytes from the SE's internal TRNG. */
	int (*get_random)(uint8_t *buf, size_t len);

	/* One-time seed provisioning. Fails SE_ERR_STATE if already set.
	 * `seed64` is the 64-byte passphrase-less BIP39 master seed
	 * (PBKDF2-HMAC-SHA512(mnemonic, "mnemonic")), i.e. the TREZOR base
	 * seed. A user passphrase is folded in later by derive_session() so it
	 * never touches persistent storage. The seed is written to SE-internal
	 * secure storage; there is NO read-back API by design. */
	int (*store_seed)(const uint8_t *seed64);

	/* Returns true if a seed has been provisioned. */
	int (*is_initialized)(bool *initialized);

	/* Returns true if a PIN has been set (independent of seed: a wiped
	 * device may still carry a PIN). Lets the UI require a PIN on first
	 * boot even before the seed exists. */
	int (*is_pin_set)(bool *set);

	/* Derive + sign inside the SE. path is a BIP32 path array (path_len
	 * uint32 components, hardened flag included). digest32 is the tx hash.
	 * Produces a 64-byte compact signature (r||s); recid out optional. */
	int (*sign_digest)(const uint32_t *path, size_t path_len,
	                   const uint8_t *digest32,
	                   uint8_t *sig64, uint8_t *recid);

	/* Get the xpub for a path (public data, safe to export). */
	int (*get_xpub)(const uint32_t *path, size_t path_len,
	                char *xpub_out, size_t xpub_max);

	/* PIN verify. Returns SE_OK on match; SE_ERR_LOCKED with
	 * *wait_seconds set while in backoff; SE_ERR_AUTH otherwise.
	 * On duress-PIN match returns SE_OK and sets *is_duress (if given). */
	int (*verify_pin)(const uint8_t *pin, size_t len,
	                  uint32_t *wait_seconds, bool *is_duress);

	/* Provision/overwrite the PIN (4..16 digits). Used by the first-boot
	 * PIN gate and factory-reset PIN enforcement. SE_OK on success. */
	int (*set_pin)(const uint8_t *pin, size_t len);

	/* Full device wipe: erase seed AND PIN (factory reset). SE_OK if the
	 * device is now blank. Must be PIN/PROVENANCE gated by the caller. */
	int (*wipe)(void);

	/* HardID passphrase derivation spec (design decision H-1, 2026-08-10):
	 *
	 *   base    = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)  [BIP39 std]
	 *   session = PBKDF2-HMAC-SHA512(base, "mnemonic" || pass, 2048) [HardID]
	 *
	 * The SE stores ONLY `base` (the passphrase-less BIP39 seed). This op
	 * folds the user passphrase into a VOLATILE session seed used for
	 * signing and xpub derivation. The session seed is never written to SE
	 * NVM — gone after wipe/power-cycle, so the passphrase is re-entered
	 * on every boot. NULL/empty passphrase clears the session back to the
	 * plain base seed. SE_OK on success.
	 *
	 * NOT BIP39-standard: BIP39 defines seed = PBKDF2(mnemonic_text, salt),
	 * while HardID chains PBKDF2(base, salt). The mnemonic text is never
	 * stored, so the standard one-shot KDF cannot be recomputed on boot.
	 * Consequences:
	 *   - Empty-passphrase accounts are FULLY BIP39-compatible (recoverable
	 *     in any standard wallet).
	 *   - Passphrase accounts live in a HardID-specific keyspace. Recovery
	 *     off-device is still possible with any PBKDF2 tool: compute base
	 *     from the mnemonic (standard BIP39, empty passphrase), then apply
	 *     the second KDF above. Reference vector: tests/test_se.c t8.
	 * The security properties (per-passphrase keyspaces, plausible
	 * deniability, wrong-passphrase -> valid-but-empty wallet) are
	 * preserved; only cross-vendor one-step recovery is given up. */
	int (*derive_session)(const uint8_t *passphrase, size_t len);

	/* Auto-sign policy: authorize amount under policy_id, or report that
	 * manual confirmation is required. Returns SE_OK if auto-approved,
	 * SE_ERR_AUTH if manual Clear Sign needed. */
	int (*policy_authorize)(uint32_t policy_id, uint64_t amount);

	/* Anti-rollback monotonic counter (firmware version floor). */
	int (*monotonic_read)(uint32_t *counter);
	int (*monotonic_increment)(void);

	/* DEV-ONLY: release the signing session lock without PIN entry. Real
	 * secure elements must set this to NULL — the build is only allowed to
	 * skip PINs when the backend actually supports re-gating. */
	int (*dev_unlock)(void);

	/* Genuine-check: sign a host challenge with the factory key so the
	 * host can verify against the vendor certificate chain. */
	int (*attest)(const uint8_t *challenge32, uint8_t *response, size_t *resp_len);
} se_driver_t;

/* Backend selection: exactly one is compiled in per build. */
const se_driver_t *se_active(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SE_H */
