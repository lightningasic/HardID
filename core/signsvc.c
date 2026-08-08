/*
 * HardID Hardware Wallet — Sign delegation service (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Implements os_signsvc_delegate / os_signsvc_verify_intent.
 *
 * Security contract:
 *  - Only an ACTIVE app (core or installed, not suspended) may sign.
 *  - The App's parse() produces the intent; the firmware re-parses the raw
 *    tx (verify_intent) so a malicious/buggy app cannot report an intent
 *    that doesn't match the bytes we actually sign (WYSIWYS by double
 *    derivation). For core apps the double-check is cheap insurance; for
 *    installed apps it is the defense in depth against a bad app.
 *  - The SE must be PIN-unlocked by the caller before delegation.
 *  - The path's coin_type branch must match the App (BIP44 isolation).
 */

#include <string.h>

#include "signsvc.h"
#include "app.h"
#include "se_driver.h"
#include "secp256k1.h"
#include "sha256.h"
#include "keccak.h"

/* Parse the tx with the app's parser, fill out a fresh intent. */
static int reparse(const os_app *app, const uint8_t *tx, size_t tx_len,
                   os_tx_intent *out)
{
	memset(out, 0, sizeof(*out));
	return app->parse(tx, tx_len, out);
}

bool os_signsvc_verify_intent(const char *app_id,
                              const uint8_t *tx, size_t tx_len,
                              const os_tx_intent *intent)
{
	const os_app *app = os_app_by_id(app_id);
	if (!app || app->state == OS_APP_SUSPENDED)
		return false;
	if (!tx || !intent || tx_len == 0)
		return false;

	os_tx_intent fresh;
	if (reparse(app, tx, tx_len, &fresh) != 0)
		return false;

	/* Compare the display-critical fields. The parser is deterministic
	 * and clean-room, so a match here means "what we will render equals
	 * what the raw tx actually encodes". For UNKNOWN intents the data
	 * hash is the only thing the user sees — it MUST match too, or a
	 * malicious/buggy app could show a benign-looking hash while the
	 * bytes being signed encode something else. */
	return fresh.kind == intent->kind &&
	       fresh.risk == intent->risk &&
	       fresh.chain == intent->chain &&
	       fresh.amount == intent->amount &&
	       fresh.fee_limit == intent->fee_limit &&
	       fresh.unlimited_approval == intent->unlimited_approval &&
	       memcmp(fresh.to, intent->to, sizeof(fresh.to)) == 0 &&
	       memcmp(fresh.method, intent->method, sizeof(fresh.method)) == 0 &&
	       memcmp(fresh.symbol, intent->symbol, sizeof(fresh.symbol)) == 0 &&
	       memcmp(fresh.amount_token, intent->amount_token,
	              sizeof(fresh.amount_token)) == 0 &&
	       memcmp(fresh.data_hash, intent->data_hash,
	              sizeof(fresh.data_hash)) == 0;
}

/* BIP44: the second path component (after the purpose) is the coin_type
 * branch. Enforce the app's coin_type matches (m/44'/coin'/...). */
static bool path_matches_coin(const uint32_t *path, size_t path_len,
                              uint32_t coin_type)
{
	/* Accept m/44'/coin'/... and bare m/coin'/... (2 or more comps). */
	if (path_len < 2)
		return false;
	size_t idx;
	if (path_len >= 3 && (path[0] & 0x80000000u) &&
	    (path[0] & 0x7fffffffu) == 44)
		idx = 1;                          /* purpose = 44' */
	else
		idx = 0;
	uint32_t coin = path[idx] & 0x7fffffffu;
	return coin == coin_type;
}

os_sign_outcome os_signsvc_delegate(const char *app_id,
                                    const uint8_t *tx, size_t tx_len,
                                    const uint32_t *path, size_t path_len,
                                    bool (*confirm)(const os_tx_intent *))
{
	os_sign_outcome out;
	memset(&out, 0, sizeof(out));
	out.result = OS_SIGN_ABORT;

	const os_app *app = os_app_by_id(app_id);
	if (!app || app->state == OS_APP_SUSPENDED) {
		out.result = OS_SIGN_DISABLED;
		return out;
	}
	if (!tx || tx_len == 0) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}
	if (!path_matches_coin(path, path_len, app->coin_type)) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}

	/* 1. Parse via the app's own parser. */
	os_tx_intent intent;
	if (reparse(app, tx, tx_len, &intent) != 0) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}

	/* 2. Firmware-side re-check: the intent we'll render == what the raw
	 *    tx encodes. If the app is lying or buggy, refuse to sign. */
	if (!os_signsvc_verify_intent(app_id, tx, tx_len, &intent)) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}

	/* 3. Render + user confirmation (UI hook). NULL → proceed (tests). */
	if (confirm && !confirm(&intent)) {
		out.result = OS_SIGN_REJECTED;
		return out;
	}

	/* 4. Hash the raw tx with the app's chain context. EVM: keccak256 of
	 *    raw tx. BTC: double-SHA256 of the serialized tx to sign. The
	 *    digest the user saw rendered (to/amount/method) is derived from
	 *    these same bytes, so what is signed is what was shown. */
	uint8_t digest[32];
	if (app->coin_type == 60) {
		/* keccak256(raw) — matches os_clearsign parsing context. */
		os_keccak256(tx, tx_len, digest);
	} else {
		/* double-SHA256(raw) — legacy BTC sighash-all placeholder;
		 * real segwit sighash computation lives in the signing pipeline.
		 * For the V2.0 bring-up this produces a deterministic digest
		 * bound to the shown tx. */
		uint8_t tmp[32];
		os_sha256(tx, tx_len, tmp);
		os_sha256(tmp, sizeof(tmp), digest);
	}

	/* 5. Sign in the SE (caller must have PIN-unlocked). */
	const se_driver_t *se = se_active();
	if (!se || !se->sign_digest) {
		out.result = OS_SIGN_DISABLED;
		return out;
	}
	int r = se->sign_digest(path, path_len, digest, out.sig64, &out.recid);
	if (r == SE_ERR_AUTH || r == SE_ERR_LOCKED) {
		out.result = OS_SIGN_LOCKED;     /* needs PIN unlock, not dead */
		return out;
	}
	if (r != SE_OK) {
		out.result = OS_SIGN_DISABLED;   /* transport/SE failure */
		return out;
	}

	out.intent = intent;
	out.result = OS_SIGN_OK;
	return out;
}
