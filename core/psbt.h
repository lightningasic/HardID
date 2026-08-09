/*
 * HardID Hardware Wallet — BTC PSBT (BIP174) parser
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Parses a PSBT enough to render a Clear Sign intent: total in, outputs
 * (address + amount), fee, and change detection. The parser is strict and
 * bounded; malformed input is rejected, never guessed.
 */

#ifndef HARDID_PSBT_H
#define HARDID_PSBT_H

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
 * coin_type selects the address encoding for outputs (BTC=0, LTC=2,
 * DOGE=3, BCH=145; see psbt.c os_btc_addr_params). Unknown coins render
 * no address (hex fallback), never a wrong-chain one.
 * change_check: optional callback — given a scriptPubKey, return true if
 * it belongs to our wallet (i.e. it's change). May be NULL (then nothing
 * is marked change). */
int os_psbt_parse(const uint8_t *psbt, size_t len,
                  bool (*change_check)(const uint8_t *script, size_t slen),
                  uint32_t coin_type,
                  os_psbt_summary *out);

/* Number of inputs in the PSBT's unsigned tx, or -1 on malformed. */
int os_btc_psbt_input_count(const uint8_t *psbt, size_t len);

/* BIP143 sighash for one input of a legacy-serialized unsigned tx.
 * witness_spk is the input's witness_utxo scriptPubKey — only native
 * P2WPKH (0014{20-byte}) is supported; anything else returns -1 (refuse,
 * never guess). sighash_type must be 1 (SIGHASH_ALL). Returns 0 / -1. */
int os_btc_bip143_sighash_tx(const uint8_t *tx, size_t tx_len,
                             uint32_t input_index,
                             const uint8_t *witness_spk, size_t spk_len,
                             uint64_t amount_sats,
                             uint32_t sighash_type,
                             uint8_t out32[32]);

/* BIP143 sighash for one input, extracted from a full PSBT (unsigned tx
 * + per-input witness_utxo + optional PSBT_IN_SIGHASH_TYPE, default ALL).
 * Returns 0 / -1 (malformed, missing witness_utxo, non-P2WPKH input, or
 * unsupported sighash type — all refused). */
int os_btc_sighash_from_psbt(const uint8_t *psbt, size_t len,
                             uint32_t input_index, uint8_t out32[32]);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_PSBT_H */
