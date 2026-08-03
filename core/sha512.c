/*
 * OpenShield Hardware Wallet — SHA-512 / HMAC-SHA512 / PBKDF2
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "sha512.h"
#include "secure_zero.h"
#include <string.h>

static const uint64_t K512[80] = {
	0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
	0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
	0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
	0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
	0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};

static uint64_t rotr64(uint64_t x, int n) { return (x >> n) | (x << (64 - n)); }

static void sha512_transform(os_sha512_ctx *c, const uint8_t *p)
{
	uint64_t w[80], a,b,cc,d,e,f,g,h,t1,t2;
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = 0;
		for (int j = 0; j < 8; j++)
			w[i] = (w[i] << 8) | p[i*8 + j];
	}
	for (i = 16; i < 80; i++) {
		uint64_t s0 = rotr64(w[i-15],1) ^ rotr64(w[i-15],8) ^ (w[i-15]>>7);
		uint64_t s1 = rotr64(w[i-2],19) ^ rotr64(w[i-2],61) ^ (w[i-2]>>6);
		w[i] = w[i-16] + s0 + w[i-7] + s1;
	}
	a=c->state[0]; b=c->state[1]; cc=c->state[2]; d=c->state[3];
	e=c->state[4]; f=c->state[5]; g=c->state[6]; h=c->state[7];
	for (i = 0; i < 80; i++) {
		uint64_t S1 = rotr64(e,14) ^ rotr64(e,18) ^ rotr64(e,41);
		uint64_t ch = (e & f) ^ ((~e) & g);
		t1 = h + S1 + ch + K512[i] + w[i];
		uint64_t S0 = rotr64(a,28) ^ rotr64(a,34) ^ rotr64(a,39);
		uint64_t maj = (a & b) ^ (a & cc) ^ (b & cc);
		t2 = S0 + maj;
		h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
	}
	c->state[0]+=a; c->state[1]+=b; c->state[2]+=cc; c->state[3]+=d;
	c->state[4]+=e; c->state[5]+=f; c->state[6]+=g; c->state[7]+=h;
}

void os_sha512_init(os_sha512_ctx *c)
{
	static const uint64_t iv[8] = {
		0x6a09e667f3bcc908ULL,0xbb67ae8584caa73bULL,0x3c6ef372fe94f82bULL,0xa54ff53a5f1d36f1ULL,
		0x510e527fade682d1ULL,0x9b05688c2b3e6c1fULL,0x1f83d9abfb41bd6bULL,0x5be0cd19137e2179ULL };
	memcpy(c->state, iv, sizeof iv);
	c->bitlen_lo = 0; c->bitlen_hi = 0;
	c->buffer_len = 0;
}

void os_sha512_update(os_sha512_ctx *c, const uint8_t *data, size_t len)
{
	uint64_t old = c->bitlen_lo;
	c->bitlen_lo += (uint64_t)len * 8;
	if (c->bitlen_lo < old) c->bitlen_hi++;
	c->bitlen_hi += (uint64_t)len >> 61;
	while (len > 0) {
		size_t take = 128 - c->buffer_len;
		if (take > len) take = len;
		memcpy(c->buffer + c->buffer_len, data, take);
		c->buffer_len += take;
		data += take;
		len -= take;
		if (c->buffer_len == 128) {
			sha512_transform(c, c->buffer);
			c->buffer_len = 0;
		}
	}
}

void os_sha512_final(os_sha512_ctx *c, uint8_t *out)
{
	uint64_t lo = c->bitlen_lo, hi = c->bitlen_hi;
	uint8_t pad = 0x80, z = 0, lenbe[16];
	for (int i = 0; i < 8; i++) {
		lenbe[i]     = (uint8_t)(hi >> ((7 - i) * 8));
		lenbe[8 + i] = (uint8_t)(lo >> ((7 - i) * 8));
	}
	os_sha512_update(c, &pad, 1);
	while (c->buffer_len != 112)
		os_sha512_update(c, &z, 1);
	os_sha512_update(c, lenbe, 16);
	for (int i = 0; i < 8; i++)
		for (int j = 0; j < 8; j++)
			out[i*8 + j] = (uint8_t)(c->state[i] >> ((7 - j) * 8));
}

void os_sha512(const uint8_t *data, size_t len, uint8_t *out64)
{
	os_sha512_ctx c;
	os_sha512_init(&c);
	os_sha512_update(&c, data, len);
	os_sha512_final(&c, out64);
}

/* ---- HMAC-SHA512 ---- */

typedef struct {
	os_sha512_ctx inner, outer;
} hmac512_ctx;

void os_hmac_sha512_init(os_hmac_sha512_ctx *ctx, const uint8_t *key, size_t klen)
{
	hmac512_ctx *h = (hmac512_ctx *)ctx->_opaque;
	uint8_t k_ipad[128], k_opad[128], key64[OS_SHA512_LEN];
	size_t i;
	if (klen > 128) {
		os_sha512(key, klen, key64);
		key = key64;
		klen = 64;
	}
	memset(k_ipad, 0x36, 128);
	memset(k_opad, 0x5c, 128);
	for (i = 0; i < klen; i++) {
		k_ipad[i] ^= key[i];
		k_opad[i] ^= key[i];
	}
	os_sha512_init(&h->inner);
	os_sha512_update(&h->inner, k_ipad, 128);
	os_sha512_init(&h->outer);
	os_sha512_update(&h->outer, k_opad, 128);
	memset(k_ipad, 0, 128);
	memset(k_opad, 0, 128);
	os_secure_bzero(key64, 64);
}

void os_hmac_sha512_update(os_hmac_sha512_ctx *ctx, const uint8_t *data, size_t len)
{
	os_sha512_update(&((hmac512_ctx *)ctx->_opaque)->inner, data, len);
}

void os_hmac_sha512_final(os_hmac_sha512_ctx *ctx, uint8_t *out64)
{
	hmac512_ctx *h = (hmac512_ctx *)ctx->_opaque;
	uint8_t inner[OS_SHA512_LEN];
	os_sha512_ctx outer = h->outer;
	os_sha512_final(&h->inner, inner);
	os_sha512_update(&outer, inner, 64);
	os_sha512_final(&outer, out64);
	os_secure_bzero(inner, 64);
}

void os_hmac_sha512(const uint8_t *key, size_t klen,
                    const uint8_t *data, size_t len, uint8_t *out64)
{
	os_hmac_sha512_ctx c;
	os_hmac_sha512_init(&c, key, klen);
	os_hmac_sha512_update(&c, data, len);
	os_hmac_sha512_final(&c, out64);
}

/* ---- PBKDF2-HMAC-SHA512 ---- */

void os_pbkdf2_sha512(const uint8_t *password, size_t plen,
                      const uint8_t *salt, size_t slen,
                      uint32_t iterations, uint8_t *out, size_t outlen)
{
	uint8_t block[OS_SHA512_LEN], u[OS_SHA512_LEN];
	uint32_t blk = 1;
	size_t produced = 0;

	while (produced < outlen) {
		/* U1 = HMAC(pw, salt || INT32_BE(blk)) */
		os_hmac_sha512_ctx c;
		os_hmac_sha512_init(&c, password, plen);
		os_hmac_sha512_update(&c, salt, slen);
		uint8_t ctr[4] = { (uint8_t)(blk >> 24), (uint8_t)(blk >> 16),
		                   (uint8_t)(blk >> 8), (uint8_t)blk };
		os_hmac_sha512_update(&c, ctr, 4);
		os_hmac_sha512_final(&c, u);
		memcpy(block, u, 64);

		for (uint32_t i = 1; i < iterations; i++) {
			os_hmac_sha512(password, plen, u, 64, u);
			for (int j = 0; j < 64; j++)
				block[j] ^= u[j];
		}
		size_t take = outlen - produced;
		if (take > 64) take = 64;
		memcpy(out + produced, block, take);
		produced += take;
		blk++;
	}
	os_secure_bzero(block, 64);
	os_secure_bzero(u, 64);
}
