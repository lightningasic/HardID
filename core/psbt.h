/*
 * OpenShield Hardware Wallet — BTC PSBT (BIP174) parser
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Parses a PSBT enough to render a Clear Sign intent: total in, outputs
 * (address + amount), fee, and change detection. The parser is strict and
 * bounded; malformed input is rejected, never guessed.
 */

#ifndef OPENSHIELD_PSBT_H
#define OPENSHIELD_PSBT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_PSBT_MAX_OUTPUTS 8
#define OS_PSBT_MAX_INPUTS  16

typedef struct {
	char     address[80];   /* bech32/base58, or script hex if unknown */
	uint64_t amount;        /* satoshi */
	bool     is_change;     /* true if belongs to our wallet (change) */
	bool     addr_valid;    /* false if we couldn't decode an address */
} os_psbt_output;

typedef struct {
	uint64_t total_in;      /* sum of input amounts (from witness_utxo) */
	uint64_t total_out;     /* sum of output amounts */
	uint64_t fee;           /* total_in - total_out */
	uint32_t input_count;
	uint32_t output_count;
	os_psbt_output outputs[OS_PSBT_MAX_OUTPUTS];
	/* outputs that are NOT change and need user confirmation */
	uint32_t spend_count;
} os_psbt_summary;

/* Parse a PSBT (BIP174, "psbt" magic) into a summary.
 * Returns 0 on success, -1 on malformed/unsupported.
 * change_check: optional callback — given a scriptPubKey, return true if
 * it belongs to our wallet (i.e. it's change). May be NULL (then nothing
 * is marked change). */
int os_psbt_parse(const uint8_t *psbt, size_t len,
                  bool (*change_check)(const uint8_t *script, size_t slen),
                  os_psbt_summary *out);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_PSBT_H */
