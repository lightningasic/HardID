/*
 * HardID Hardware Wallet — Base58Check encoding
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "base58.h"
#include "sha256.h"
#include <string.h>

static const char B58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

void os_sha256d(const uint8_t *data, size_t len, uint8_t *out32)
{
	uint8_t tmp[OS_SHA256_LEN];
	os_sha256(data, len, tmp);
	os_sha256(tmp, OS_SHA256_LEN, out32);
	memset(tmp, 0, sizeof tmp);
}

size_t os_base58_encode_check(const uint8_t *data, size_t len,
                              char *out, size_t outmax)
{
	if (len == 0 || len > 96)
		return 0;
	uint8_t buf[100];                    /* data + 4-byte checksum */
	memcpy(buf, data, len);
	uint8_t hash[OS_SHA256_LEN];
	os_sha256d(data, len, hash);
	memcpy(buf + len, hash, 4);
	size_t total = len + 4;

	/* count leading zeros */
	size_t zeros = 0;
	while (zeros < total && buf[zeros] == 0)
		zeros++;

	/* big-number base58 conversion */
	uint8_t b58[140];
	size_t b58len = 0;
	for (size_t i = zeros; i < total; i++) {
		uint32_t carry = buf[i];
		for (size_t j = 0; j < b58len; j++) {
			carry += (uint32_t)b58[j] << 8;
			b58[j] = carry % 58;
			carry /= 58;
		}
		while (carry) {
			b58[b58len++] = carry % 58;
			carry /= 58;
		}
	}

	size_t need = zeros + b58len;
	if (need + 1 > outmax)
		return 0;
	size_t o = 0;
	for (size_t i = 0; i < zeros; i++)
		out[o++] = '1';
	for (size_t i = 0; i < b58len; i++)
		out[o++] = B58[b58[b58len - 1 - i]];
	out[o] = 0;
	return o;
}

size_t os_base58check_encode(uint8_t version, const uint8_t *payload20,
                             char *out, size_t outmax)
{
	uint8_t data[21];
	data[0] = version;
	memcpy(data + 1, payload20, 20);
	return os_base58_encode_check(data, 21, out, outmax);
}
