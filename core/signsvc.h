/*
 * HardID Hardware Wallet — Sign delegation service (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The ONLY path to a signature. An App (parser plugin) may submit a sign
 * request with the raw tx and its parsed intent; the firmware renders the
 * intent on screen, requires user confirmation, verifies the intent matches
 * the tx, then signs inside the SE. The App never sees a private key and
 * cannot sign anything the user did not confirm.
 *
 * Design contract (see docs/04_软件工程 V2.0 §3.3):
 *  - intent hash is fixed by the firmware BEFORE rendering
 *  - the same intent struct drives display and signing (WYSIWYS)
 *  - path is checked against the App's coin_type branch before signing
 */

#ifndef HARDID_SIGNSVC_H
#define HARDID_SIGNSVC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "clearsign.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Result of rendering + user confirmation, returned to the App/UI. */
typedef enum {
	OS_SIGN_OK,          /* confirmed and signed */
	OS_SIGN_REJECTED,    /* user declined */
	OS_SIGN_ABORT,       /* cancelled (UI back / PIN abort) */
	OS_SIGN_DISABLED,    /* app suspended / not found / not initialized */
	OS_SIGN_PARSE_ERR,   /* tx malformed */
	OS_SIGN_LOCKED,      /* SE session not PIN-unlocked */
} os_sign_result;

/* Outcome of a sign request. */
typedef struct {
	os_sign_result result;
	uint8_t        sig64[64];  /* valid when result == OS_SIGN_OK */
	uint8_t        recid;
	os_tx_intent   intent;     /* the intent that was confirmed/signed */
} os_sign_outcome;

/*
 * Delegate a sign request: parse via app, render, confirm, sign in SE.
 *
 *  app_id    — App id ("btc", "eth", ...). Firmware looks up the app,
 *              checks it is active, and uses its parse().
 *  tx        — raw transaction bytes (PSBT / EVM raw / custom).
 *  tx_len    — length.
 *  path      — BIP32 path components (hardened flag included). The
 *              coin_type branch must match the app's coin_type.
 *  path_len  — number of path components.
 *  confirm   — UI callback that renders `intent` and asks the user;
 *              returns true if confirmed, false if rejected. NULL is a
 *              TEST-ONLY bypass, compiled out of production builds (see
 *              CONFIG_SIGNSVC_ALLOW_NULL_CONFIRM / HARDID_HOST_TEST); a
 *              production build passes NULL → OS_SIGN_ABORT, it never
 *              silently signs.
 *
 * The SE must already be PIN-unlocked by the caller (boot/UI policy).
 * Returns the outcome; signature present iff result == OS_SIGN_OK.
 */
os_sign_outcome os_signsvc_delegate(const char *app_id,
                                    const uint8_t *tx, size_t tx_len,
                                    const uint32_t *path, size_t path_len,
                                    bool (*confirm)(const os_tx_intent *));

/*
 * Verify a parsed intent is consistent with the raw tx WITHOUT signing.
 * This is the firmware-side INDEPENDENT intent check: it re-derives the
 * intent from the tx with the firmware's own clean-room parser (dispatched
 * by coin_type) — NOT the App's parse() — and requires an exact match.
 * Returns true only if the firmware can parse the chain AND the App's
 * reported intent matches the firmware's independent derivation. Chains
 * with no firmware parser are refused (returns false): WYSIWYS cannot be
 * proven, so such chains must land a firmware parser before signing.
 */
bool os_signsvc_verify_intent(const char *app_id,
                              const uint8_t *tx, size_t tx_len,
                              const os_tx_intent *intent);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SIGNSVC_H */
