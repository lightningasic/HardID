/*
 * HardID Hardware Wallet — Sign delegation service (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Implements os_signsvc_delegate / os_signsvc_verify_intent.
 *
 * Security contract:
 *  - Only an ACTIVE app (core or installed, not suspended) may sign.
 *  - The App's parse() produces the candidate intent; the firmware then
 *    INDEPENDENTLY re-derives the intent from the raw bytes with its own
 *    clean-room parser (fw_reparse, dispatched by coin_type) and requires
 *    an exact match. A malicious/buggy App therefore cannot cause the user
 *    to confirm an intent that does not match the bytes actually signed
 *    (WYSIWYS by independent double-derivation, NOT by re-running the
 *    App's own parser).
 *  - Chains without a firmware parser are refused: the official-review
 *    market requires a firmware-side parser to land before a new chain's
 *    App can sign.
 *  - The SE must be PIN-unlocked by the caller before delegation.
 *  - The path's coin_type branch must match the App (BIP44 isolation).
 */

#include <string.h>
#include <stdio.h>

#include "signsvc.h"
#include "app.h"
#include "se_driver.h"
#include "secp256k1.h"
#include "sha256.h"
#include "keccak.h"

/* Parse the tx with the app's parser, fill out a fresh intent. The app's
 * own coin_type is passed so a shared catalog parser renders per-coin
 * address encodings (LTC gets ltc1…, not bc1…). */
static int reparse(const os_app *app, const uint8_t *tx, size_t tx_len,
                   os_tx_intent *out)
{
	memset(out, 0, sizeof(*out));
	return app->parse(tx, tx_len, app->coin_type, out);
}

/* Canonical native-symbol for a coin_type. The firmware parsers only know
 * their own native format (the BTC/PSBT parser hardcodes "BTC"; the EVM
 * parser sets no symbol), but a catalog app (LTC/DOGE/BCH/ETC/POLYGON)
 * reuses those parsers — so its intent would show the WRONG native symbol
 * on the confirm screen. Normalize by BIP44 coin_type so what the user
 * confirms matches the chain they selected. Applies AFTER both the App's
 * parse and the firmware re-parse so the double-derivation stays in lockstep. */
static const char *coin_native_symbol(uint32_t coin_type)
{
	switch (coin_type) {
	case 0:    return "BTC";
	case 2:    return "LTC";
	case 3:    return "DOGE";
	case 145:  return "BCH";
	case 60:   return "ETH";
	case 61:   return "ETC";
	case 966:  return "POL";
	default:   return NULL;
	}
}

static void apply_native_symbol(uint32_t coin_type, os_tx_intent *o)
{
	const char *sym = coin_native_symbol(coin_type);
	if (sym)
		snprintf(o->symbol, sizeof(o->symbol), "%s", sym);
}

/* Firmware clean-room re-parse, INDEPENDENT of the App's parse(). This is
 * the WYSIWYS anchor: the intent the user confirms must match what the
 * firmware itself derives from the raw bytes, NOT merely what the App
 * claims. Dispatched by coin_type so a malicious/buggy App parser can never
 * be the sole source of the displayed intent. Returns 0 on success, -1 if
 * the firmware has no parser for this chain (unknown third-party chain —
 * refuse to sign; such chains require a firmware-side parser landing first,
 * consistent with the official-review market model). */
static int fw_reparse(uint32_t coin_type, const uint8_t *tx, size_t tx_len,
                      os_tx_intent *out)
{
	memset(out, 0, sizeof(*out));
	/* Dispatch by PARSER CAPABILITY, not by coin list: a catalog app that
	 * reuses a firmware clean-room parser (e.g. LTC/DOGE/BCH share the PSBT
	 * parser, ETC/POLYGON share the EVM parser) must be verified by the
	 * SAME firmware parser, or the market would install apps that can never
	 * sign. These parsers are all firmware-owned and officially reviewed,
	 * so the WYSIWYS anchor holds for every listed chain. */
	switch (coin_type) {
	case 0:  /* BTC */
	case 2:  /* LTC */
	case 3:  /* DOGE */
	case 145:/* BCH */
		return os_clearsign_parse_btc_coin(tx, tx_len, coin_type, out);
	case 60: /* ETH / EVM */
	case 61: /* ETC */
	case 966:/* POLYGON */
		return os_clearsign_parse_evm_coin(tx, tx_len, coin_type, out);
	default:
		return -1;   /* no firmware parser → cannot independently verify */
	}
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
	/* INDEPENDENT firmware re-derivation: never re-run the App's own
	 * parser here, or a malicious App would trivially "verify" itself.
	 * If the firmware cannot parse this chain it cannot prove WYSIWYS,
	 * so it refuses. */
	if (fw_reparse(app->coin_type, tx, tx_len, &fresh) != 0)
		return false;

	/* Normalize the native symbol on LOCAL COPIES before comparing, so a
	 * catalog chain (LTC via the BTC parser, ETC via the EVM parser) shows
	 * its own token and the two derivations stay identical. The caller's
	 * intent is never mutated. */
	os_tx_intent shown = *intent;
	apply_native_symbol(app->coin_type, &fresh);
	apply_native_symbol(app->coin_type, &shown);

	/* Compare the display-critical fields. The parser is deterministic
	 * and clean-room, so a match here means "what we will render equals
	 * what the raw tx actually encodes". For UNKNOWN intents the data
	 * hash is the only thing the user sees — it MUST match too, or a
	 * malicious/buggy app could show a benign-looking hash while the
	 * bytes being signed encode something else. */
	return fresh.kind == shown.kind &&
	       fresh.risk == shown.risk &&
	       fresh.chain == shown.chain &&
	       fresh.amount == shown.amount &&
	       fresh.fee_limit == shown.fee_limit &&
	       fresh.unlimited_approval == shown.unlimited_approval &&
	       fresh.chain_id == shown.chain_id &&
	       memcmp(fresh.to, shown.to, sizeof(fresh.to)) == 0 &&
	       memcmp(fresh.method, shown.method, sizeof(fresh.method)) == 0 &&
	       memcmp(fresh.symbol, shown.symbol, sizeof(fresh.symbol)) == 0 &&
	       memcmp(fresh.amount_token, shown.amount_token,
	              sizeof(fresh.amount_token)) == 0 &&
	       memcmp(fresh.data_hash, shown.data_hash,
	              sizeof(fresh.data_hash)) == 0;
}

/* BIP44-style isolation: require a hardened purpose from a whitelist, a
 * hardened coin_type branch matching the app, and a hardened account.
 * Accepted shapes (all three levels hardened):
 *   m/44'/coin'/acct'/...   (legacy)
 *   m/49'/coin'/acct'/...   (P2SH-SegWit)
 *   m/84'/coin'/acct'/...   (native SegWit)
 *   m/86'/coin'/acct'/...   (Taproot)
 * Anything else — non-hardened levels, unknown purpose, bare m/coin — is
 * rejected so a path can never escape the app's coin/account isolation. */
#define OS_PATH_HARDENED 0x80000000u

static bool path_matches_coin(const uint32_t *path, size_t path_len,
                              uint32_t coin_type)
{
	if (!path || path_len < 3)
		return false;
	uint32_t purpose = path[0] & ~OS_PATH_HARDENED;
	if ((path[0] & OS_PATH_HARDENED) == 0)
		return false;                      /* purpose must be hardened */
	switch (purpose) {
	case 44: case 49: case 84: case 86:
		break;
	default:
		return false;                      /* unknown purpose */
	}
	uint32_t coin = path[1];
	if ((coin & OS_PATH_HARDENED) == 0)
		return false;                      /* coin branch must be hardened */
	if ((coin & ~OS_PATH_HARDENED) != coin_type)
		return false;                      /* must match the app's coin_type */
	if (path_len >= 3 && (path[2] & OS_PATH_HARDENED) == 0)
		return false;                      /* account must be hardened */
	return true;
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

	/* 1. Parse via the app's own parser → the CANDIDATE intent. */
	os_tx_intent intent;
	if (reparse(app, tx, tx_len, &intent) != 0) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}
	/* Show the chain's native symbol, not the parser's (a catalog reuse of
	 * the BTC/PSBT parser would otherwise render "BTC" for a Litecoin tx). */
	apply_native_symbol(app->coin_type, &intent);

	/* 2. Firmware INDEPENDENT re-derivation + exact-match check: the intent
	 *    we render must equal what the firmware itself parses from the raw
	 *    bytes. If the app is lying or buggy, refuse to sign. Chains with
	 *    no firmware parser are refused inside verify_intent. */
	if (!os_signsvc_verify_intent(app_id, tx, tx_len, &intent)) {
		out.result = OS_SIGN_PARSE_ERR;
		return out;
	}

	/* 3. Render + user confirmation (UI hook). A NULL confirm is ALWAYS a
	 *    hard abort: there is no test bypass, and no build configuration
	 *    compiles in signing without an explicit on-device confirmation. */
	if (!confirm) {
		out.result = OS_SIGN_ABORT;
		return out;
	}
	if (!confirm(&intent)) {
		out.result = OS_SIGN_REJECTED;
		return out;
	}

	/* 4+5. Real chain sighash (M-2) + SE signing. The digest the user saw
	 *    rendered (to/amount/method) is derived from these same bytes, so
	 *    what is signed is what was shown. */
	const se_driver_t *se = se_active();
	if (!se || !se->sign_digest) {
		out.result = OS_SIGN_DISABLED;
		return out;
	}

	if (app->coin_type == 60 || app->coin_type == 61 || app->coin_type == 966) {
		/* EVM: EIP-155 legacy injection / typed envelope, chainId
		 * enforced against the app's expected chain. One signature. */
		uint8_t digest[32];
		if (os_evm_sighash(tx, tx_len,
		                   os_evm_chain_id_for_coin(app->coin_type),
		                   digest) != 0) {
			out.result = OS_SIGN_PARSE_ERR;
			return out;
		}
		int r = se->sign_digest(path, path_len, digest, out.sig64, &out.recid);
		if (r == SE_ERR_AUTH || r == SE_ERR_LOCKED) {
			out.result = OS_SIGN_LOCKED;
			return out;
		}
		if (r != SE_OK) {
			out.result = OS_SIGN_DISABLED;
			return out;
		}
		out.sigs[0][0] = 0;  /* unused for EVM; sig64 is canonical */
		out.sig_count = 1;
	} else {
		/* BTC-family: one BIP143 sighash per PSBT input, each signed.
		 * The host assembles the witnesses. Only native P2WPKH inputs
		 * with SIGHASH_ALL are supported — anything else refuses. */
		int nin = os_btc_psbt_input_count(tx, tx_len);
		if (nin <= 0) {
			out.result = OS_SIGN_PARSE_ERR;
			return out;
		}
		for (int i = 0; i < nin; i++) {
			uint8_t digest[32];
			if (os_btc_sighash_from_psbt(tx, tx_len, (uint32_t)i,
			                             digest) != 0) {
				out.result = OS_SIGN_PARSE_ERR;
				return out;
			}
			int r = se->sign_digest(path, path_len, digest,
			                        out.sigs[i], &out.recids[i]);
			if (r == SE_ERR_AUTH || r == SE_ERR_LOCKED) {
				out.result = OS_SIGN_LOCKED;
				return out;
			}
			if (r != SE_OK) {
				out.result = OS_SIGN_DISABLED;
				return out;
			}
		}
		out.sig_count = (uint32_t)nin;
		memcpy(out.sig64, out.sigs[0], 64);
		out.recid = out.recids[0];
	}

	out.intent = intent;
	out.result = OS_SIGN_OK;
	return out;
}
