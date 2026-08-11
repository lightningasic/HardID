/*
 * HardID Hardware Wallet — unconditional entropy pool (SHA-256 mixing)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "phys_entropy.h"
#include "sha256.h"
#include "secure_zero.h"
#include <string.h>

/* Chained mixing using the exported one-shot os_sha256 (the incremental
 * SHA-256 core in hkdf.c is static). Source bytes are folded in bounded
 * chunks so len needs no length-limit. Every mix is domain-separated by a
 * tag byte + length prefix, keeping the construction prefix-safe. */

#define ABSORB_CHUNK 32

static void mix_one(os_phys_pool_t *p, uint8_t tag,
		    const uint8_t *data, size_t len)
{
	uint8_t in[1 + OS_PHYS_POOL_LEN + 4];
	uint8_t out[OS_PHYS_POOL_LEN];

	in[0] = tag;
	memcpy(in + 1, p->st, OS_PHYS_POOL_LEN);
	in[1 + OS_PHYS_POOL_LEN + 0] = (uint8_t)(len >> 24);
	in[1 + OS_PHYS_POOL_LEN + 1] = (uint8_t)(len >> 16);
	in[1 + OS_PHYS_POOL_LEN + 2] = (uint8_t)(len >> 8);
	in[1 + OS_PHYS_POOL_LEN + 3] = (uint8_t)(len & 0xff);

	os_sha256(in, sizeof in, out);
	os_secure_bzero(in, sizeof in);

	if (data && len > 0) {
		/* fold data in blocks; each block re-uses the tag-0x03 mix */
		size_t off = 0;
		while (off < len) {
			size_t chunk = len - off;
			if (chunk > ABSORB_CHUNK) chunk = ABSORB_CHUNK;
			uint8_t in2[1 + OS_PHYS_POOL_LEN + 4 + ABSORB_CHUNK];
			in2[0] = 0x03;
			memcpy(in2 + 1, out, OS_PHYS_POOL_LEN);
			in2[1 + OS_PHYS_POOL_LEN + 0] = (uint8_t)(chunk >> 24);
			in2[1 + OS_PHYS_POOL_LEN + 1] = (uint8_t)(chunk >> 16);
			in2[1 + OS_PHYS_POOL_LEN + 2] = (uint8_t)(chunk >> 8);
			in2[1 + OS_PHYS_POOL_LEN + 3] = (uint8_t)(chunk & 0xff);
			memcpy(in2 + 1 + OS_PHYS_POOL_LEN + 4,
			       data + off, chunk);
			os_sha256(in2, sizeof in2, out);
			os_secure_bzero(in2, sizeof in2);
			off += chunk;
		}
	}

	memcpy(p->st, out, OS_PHYS_POOL_LEN);
	os_secure_bzero(out, sizeof out);
}

void os_phys_pool_init(os_phys_pool_t *p)
{
	memset(p, 0, sizeof(*p));
}

void os_phys_pool_absorb(os_phys_pool_t *p, const uint8_t *data, size_t len)
{
	if (!p || p->used)
		return;
	mix_one(p, 0x01, data, len);
}

void os_phys_pool_extract(os_phys_pool_t *p, uint8_t *out, size_t out_len)
{
	if (!p || p->used || !out || out_len == 0) {
		if (out && out_len)
			memset(out, 0, out_len);
		return;
	}

	mix_one(p, 0x02, NULL, out_len);
	if (out_len > OS_PHYS_POOL_LEN) {
		/* pool is 32 bytes; never leave caller bytes uninitialized */
		memset(out + OS_PHYS_POOL_LEN, 0, out_len - OS_PHYS_POOL_LEN);
		out_len = OS_PHYS_POOL_LEN;
	}
	memcpy(out, p->st, out_len);
	os_secure_bzero(p, sizeof(*p));   /* single-use: wipe state */
	p->used = 1;
}
