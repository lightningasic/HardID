/*
 * OpenShield Hardware Wallet — EIP-712 typed structured data
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * EIP-712 hashing: domain separator + struct hash, per the standard
 *   digest = keccak256("\x19\x01" || domainSeparator || hashStruct(message))
 *
 * This module builds the digest the user is asked to sign and renders the
 * salient fields for Clear Sign display. It deliberately supports a bounded
 * subset of types (the common DeFi/permit shapes); anything outside the
 * subset is surfaced as opaque bytes with a hash for the UI to warn on.
 */

#ifndef OPENSHIELD_EIP712_H
#define OPENSHIELD_EIP712_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EIP-712 domain separator fields (all optional except name for display). */
typedef struct {
	char     name[64];
	char     version[16];
	uint64_t chain_id;
	uint8_t  verifying_contract[20];
	int      has_chain_id;
	int      has_contract;
} os_eip712_domain;

/* Compute the EIP-712 domain separator for the common domain shape
 * (name, version, chainId, verifyingContract). salt not supported. */
void os_eip712_domain_separator(const os_eip712_domain *dom, uint8_t *out32);

/* Assemble the final signing digest:
 *   keccak256("\x19\x01" || domain_separator || message_struct_hash) */
void os_eip712_digest(const uint8_t domain_sep32[32],
                      const uint8_t struct_hash32[32],
                      uint8_t *out32);

/* ---- Typed-data struct hashing helpers ---- */

/* keccak256 of a type string, e.g. "Permit(address owner,address spender,
 * uint256 value,uint256 nonce,uint256 deadline)" */
void os_eip712_type_hash(const char *type_string, uint8_t *out32);

/* Encode one 32-byte word field (address left-padded / uint256 big-endian)
 * into the running struct hash buffer at offset (offset must be < 32*16). */
void os_eip712_encode_address(uint8_t *buf, size_t offset, const uint8_t addr20[20]);
void os_eip712_encode_uint256(uint8_t *buf, size_t offset, const uint8_t val32[32]);
void os_eip712_encode_bytes32(uint8_t *buf, size_t offset, const uint8_t val32[32]);

/* hashStruct = keccak256(typeHash || encodeData(fields...)). fields is the
 * buffer built by the encode_* helpers, fields_len its length. */
void os_eip712_hash_struct(const uint8_t type_hash32[32],
                           const uint8_t *fields, size_t fields_len,
                           uint8_t *out32);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_EIP712_H */
