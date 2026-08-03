/*
 * OpenShield Hardware Wallet — EIP-712 typed structured data
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "eip712.h"
#include "keccak.h"
#include <string.h>
#include <stdio.h>

void os_eip712_type_hash(const char *type_string, uint8_t *out32)
{
	os_keccak256((const uint8_t *)type_string, strlen(type_string), out32);
}

void os_eip712_encode_address(uint8_t *buf, size_t offset, const uint8_t addr20[20])
{
	memset(buf + offset, 0, 12);
	memcpy(buf + offset + 12, addr20, 20);
}
void os_eip712_encode_uint256(uint8_t *buf, size_t offset, const uint8_t val32[32])
{
	memcpy(buf + offset, val32, 32);
}
void os_eip712_encode_bytes32(uint8_t *buf, size_t offset, const uint8_t val32[32])
{
	memcpy(buf + offset, val32, 32);
}

void os_eip712_hash_struct(const uint8_t type_hash32[32],
                           const uint8_t *fields, size_t fields_len,
                           uint8_t *out32)
{
	os_keccak_ctx c;
	os_keccak256_init(&c);
	os_keccak256_update(&c, type_hash32, 32);
	if (fields && fields_len)
		os_keccak256_update(&c, fields, fields_len);
	os_keccak256_final(&c, out32);
}

void os_eip712_domain_separator(const os_eip712_domain *dom, uint8_t *out32)
{
	/* type: EIP712Domain(string name,string version,uint256 chainId,
	 *                    address verifyingContract) */
	uint8_t type_hash[32];
	os_eip712_type_hash(
		"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
		type_hash);

	/* fields: keccak(name), keccak(version), chainId, contract */
	uint8_t fields[32 * 4];
	uint8_t th[32];

	os_keccak256((const uint8_t *)dom->name, strlen(dom->name), th);
	memcpy(fields + 0, th, 32);
	os_keccak256((const uint8_t *)dom->version, strlen(dom->version), th);
	memcpy(fields + 32, th, 32);

	memset(fields + 64, 0, 32);
	fields[64 + 24] = (uint8_t)(dom->chain_id >> 56);
	fields[64 + 25] = (uint8_t)(dom->chain_id >> 48);
	fields[64 + 26] = (uint8_t)(dom->chain_id >> 40);
	fields[64 + 27] = (uint8_t)(dom->chain_id >> 32);
	fields[64 + 28] = (uint8_t)(dom->chain_id >> 24);
	fields[64 + 29] = (uint8_t)(dom->chain_id >> 16);
	fields[64 + 30] = (uint8_t)(dom->chain_id >> 8);
	fields[64 + 31] = (uint8_t)(dom->chain_id);

	os_eip712_encode_address(fields, 96, dom->verifying_contract);

	os_eip712_hash_struct(type_hash, fields, sizeof fields, out32);
	memset(fields, 0, sizeof fields);
}

void os_eip712_digest(const uint8_t domain_sep32[32],
                      const uint8_t struct_hash32[32],
                      uint8_t *out32)
{
	os_keccak_ctx c;
	os_keccak256_init(&c);
	os_keccak256_update(&c, (const uint8_t *)"\x19\x01", 2);
	os_keccak256_update(&c, domain_sep32, 32);
	os_keccak256_update(&c, struct_hash32, 32);
	os_keccak256_final(&c, out32);
}
