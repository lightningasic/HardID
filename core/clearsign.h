/*
 * OpenShield Hardware Wallet — Clear Sign engine
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Parses a transaction into a human-readable intent and assigns a risk
 * level. The display renders from THIS struct — the same struct the signer
 * consumes — so "what you see is what you sign" holds by construction.
 * Anything unparseable is degraded to UNKNOWN with a data hash; the UI must
 * require a long-press confirmation for UNKNOWN, never guess.
 */

#ifndef OPENSHIELD_CLEARSIGN_H
#define OPENSHIELD_CLEARSIGN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	OS_CHAIN_BTC,
	OS_CHAIN_ETH,
} os_chain;

typedef enum {
	OS_INTENT_TRANSFER,       /* native coin transfer */
	OS_INTENT_ERC20_TRANSFER, /* token transfer (known method) */
	OS_INTENT_ERC20_APPROVE,  /* token approval — surface spender+amount */
	OS_INTENT_CONTRACT_CALL,  /* recognized contract call */
	OS_INTENT_UNKNOWN,        /* unparseable — must warn, long-press */
} os_intent_kind;

typedef enum {
	OS_RISK_LOW,      /* simple transfer, recognized */
	OS_RISK_MEDIUM,   /* approval / contract call, recognized */
	OS_RISK_HIGH,     /* unknown calldata, unlimited approval, etc. */
} os_risk;

typedef struct {
	os_chain chain;
	os_intent_kind kind;
	os_risk risk;

	/* display fields (NUL-terminated where applicable) */
	char     to[48];          /* recipient / spender address (0x + 40 hex) */
	uint64_t amount;          /* native amount in wei/satoshi */
	char     amount_token[32];/* formatted token amount (if token) */
	uint64_t fee_limit;       /* max fee (gasLimit*maxFee or vsize*feerate) */
	char     method[32];      /* contract method name, or "" */
	char     symbol[12];      /* token symbol, or "" */
	bool     unlimited_approval;

	/* raw calldata hash for UNKNOWN (first 4 bytes = selector) */
	uint8_t  data_hash[32];
} os_tx_intent;

/* Parse a raw EVM transaction (RLP, legacy or EIP-1559) into intent.
 * Returns 0 on success, -1 on malformed input. On success, fields are
 * populated; unparseable calldata sets kind=UNKNOWN + data_hash. */
int os_clearsign_parse_evm(const uint8_t *raw_tx, size_t len,
                           os_tx_intent *out);

/* Well-known 4-byte selectors we can name. Extend as needed. */
const char *os_clearsign_method_name(const uint8_t selector[4]);

/* Convenience: is this an unlimited (uint256 max) approval amount? */
bool os_clearsign_is_unlimited_amount(const uint8_t amount32[32]);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_CLEARSIGN_H */
