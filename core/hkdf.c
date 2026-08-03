/*
 * OpenShield Hardware Wallet — HKDF-SHA256 (RFC 5869)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "hkdf.h"
#include "sha256.h"
#include <string.h>

/* ---- minimal self-contained SHA-256 ---- */

typedef struct {
	uint32_t state[8];
	uint64_t bitlen;
	uint8_t  buffer[64];
	size_t   buffer_len;
} sha256_ctx;

static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static uint32_t rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_transform(sha256_ctx *c, const uint8_t *p)
{
	uint32_t w[64], a,b,c2,d,e,f,g,h,t1,t2;
	int i;
	for (i = 0; i < 16; i++)
		w[i] = (uint32_t)p[i*4]<<24 | (uint32_t)p[i*4+1]<<16 |
		       (uint32_t)p[i*4+2]<<8 | (uint32_t)p[i*4+3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>3);
		uint32_t s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>10);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a=c->state[0]; b=c->state[1]; c2=c->state[2]; d=c->state[3];
	e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = rotr(e,6) ^ rotr(e,11) ^ rotr(e,25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		t1 = h + S1 + ch + K[i] + w[i];
		uint32_t S0 = rotr(a,2) ^ rotr(a,13) ^ rotr(a,22);
		uint32_t maj = (a & b) ^ (a & c2) ^ (b & c2);
		t2 = S0 + maj;
		h=g; g=f; f=e; e=d+t1; d=c2; c2=b; b=a; a=t1+t2;
	}
	c->state[0]+=a; c->state[1]+=b; c->state[2]+=c2; c->state[3]+=d;
	c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

static void sha256_init(sha256_ctx *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
		0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	memcpy(c->state, iv, sizeof iv);
	c->bitlen = 0;
	c->buffer_len = 0;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len)
{
	c->bitlen += (uint64_t)len * 8;
	while (len > 0) {
		size_t take = 64 - c->buffer_len;
		if (take > len) take = len;
		memcpy(c->buffer + c->buffer_len, data, take);
		c->buffer_len += take;
		data += take;
		len -= take;
		if (c->buffer_len == 64) {
			sha256_transform(c, c->buffer);
			c->buffer_len = 0;
		}
	}
}

static void sha256_final(sha256_ctx *c, uint8_t *out)
{
	uint64_t bits = c->bitlen;
	uint8_t pad = 0x80;
	uint8_t lenbe[8];
	int i;
	for (i = 0; i < 8; i++)
		lenbe[7-i] = (uint8_t)(bits >> (i * 8));
	sha256_update(c, &pad, 1);
	{
		uint8_t z = 0;
		while (c->buffer_len != 56)
			sha256_update(c, &z, 1);
	}
	sha256_update(c, lenbe, 8);
	for (i = 0; i < 8; i++) {
		out[i*4]   = (uint8_t)(c->state[i] >> 24);
		out[i*4+1] = (uint8_t)(c->state[i] >> 16);
		out[i*4+2] = (uint8_t)(c->state[i] >> 8);
		out[i*4+3] = (uint8_t)(c->state[i]);
	}
}

/* public one-shot SHA-256 for modules that only need the hash */
void os_sha256(const uint8_t *data, size_t len, uint8_t *out32)
{
	sha256_ctx c;
	sha256_init(&c);
	sha256_update(&c, data, len);
	sha256_final(&c, out32);
}

/* ---- HMAC-SHA256 context storing both pad states ---- */

typedef struct {
	sha256_ctx inner;
	sha256_ctx outer;
} hmac_ctx;

void os_hmac_sha256_init(os_hmac_sha256_ctx_storage *ctx,
                         const uint8_t *key, size_t key_len)
{
	hmac_ctx *h = (hmac_ctx *)ctx->_opaque;
	uint8_t k_ipad[64], k_opad[64], key32[OS_HKDF_SHA256_LEN];
	size_t i;

	if (key_len > 64) {
		sha256_ctx t;
		sha256_init(&t);
		sha256_update(&t, key, key_len);
		sha256_final(&t, key32);
		key = key32;
		key_len = 32;
	}
	memset(k_ipad, 0x36, 64);
	memset(k_opad, 0x5c, 64);
	for (i = 0; i < key_len; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}
	sha256_init(&h->inner);
	sha256_update(&h->inner, k_ipad, 64);
	sha256_init(&h->outer);
	sha256_update(&h->outer, k_opad, 64);
	memset(k_ipad, 0, 64);
	memset(k_opad, 0, 64);
	memset(key32, 0, 32);
}

void os_hmac_sha256_update(os_hmac_sha256_ctx_storage *ctx,
                           const uint8_t *data, size_t len)
{
	hmac_ctx *h = (hmac_ctx *)ctx->_opaque;
	sha256_update(&h->inner, data, len);
}

void os_hmac_sha256_final(os_hmac_sha256_ctx_storage *ctx, uint8_t *out32)
{
	hmac_ctx *h = (hmac_ctx *)ctx->_opaque;
	uint8_t inner[OS_HKDF_SHA256_LEN];
	sha256_ctx outer = h->outer;
	sha256_final(&h->inner, inner);
	sha256_update(&outer, inner, 32);
	sha256_final(&outer, out32);
	memset(inner, 0, 32);
}

void os_hmac_sha256(const uint8_t *key, size_t key_len,
                    const uint8_t *data, size_t len, uint8_t *out32)
{
	os_hmac_sha256_ctx_storage h;
	os_hmac_sha256_init(&h, key, key_len);
	os_hmac_sha256_update(&h, data, len);
	os_hmac_sha256_final(&h, out32);
}

/* ---- HKDF (RFC 5869) ---- */

void os_hkdf_expand32(const uint8_t *prk32,
                      const uint8_t *info, size_t info_len,
                      uint8_t *out32)
{
	os_hmac_sha256_ctx_storage h;
	static const uint8_t one = 0x01;
	os_hmac_sha256_init(&h, prk32, 32);
	os_hmac_sha256_update(&h, info, info_len);
	os_hmac_sha256_update(&h, &one, 1);
	os_hmac_sha256_final(&h, out32);
}

void os_hkdf_sha256(const uint8_t *salt, size_t salt_len,
                    const uint8_t *ikm, size_t ikm_len,
                    const uint8_t *info, size_t info_len,
                    uint8_t *out32)
{
	uint8_t prk[32];
	os_hmac_sha256_ctx_storage h;
	/* Extract */
	os_hmac_sha256_init(&h, salt, salt_len);
	os_hmac_sha256_update(&h, ikm, ikm_len);
	os_hmac_sha256_final(&h, prk);
	/* Expand (single block) */
	os_hkdf_expand32(prk, info, info_len, out32);
	memset(prk, 0, 32);
}
