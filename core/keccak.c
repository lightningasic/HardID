/*
 * OpenShield Hardware Wallet — Keccak-256 (Ethereum variant)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation of Keccak-f[1600].
 * Not derived from TREZOR code. License: Apache License 2.0
 */

#include "keccak.h"
#include <string.h>

#define KECCAK_ROUNDS 24
#define RATE_BYTES 136   /* 1088 bits */

static const uint64_t RC[KECCAK_ROUNDS] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 	0x0000000080000001ULL, 0x8000000080008008ULL
};

/* rotation offsets r[x][y] indexed by lane (x + 5*y) */
static const int ROT[25] = {
	 0,  1, 62, 28, 27,
	36, 44,  6, 55, 20,
	 3, 10, 43, 25, 39,
	41, 45, 15, 21,  8,
	18,  2, 61, 56, 14
};

static uint64_t rol64(uint64_t x, int n)
{
	return n ? ((x << n) | (x >> (64 - n))) : x;
}

static void keccak_f(uint64_t s[25])
{
	uint64_t b[5], t;
	for (int round = 0; round < KECCAK_ROUNDS; round++) {
		/* theta */
		for (int x = 0; x < 5; x++)
			b[x] = s[x] ^ s[x+5] ^ s[x+10] ^ s[x+15] ^ s[x+20];
		for (int x = 0; x < 5; x++) {
			t = b[(x+4)%5] ^ rol64(b[(x+1)%5], 1);
			for (int y = 0; y < 5; y++)
				s[x + 5*y] ^= t;
		}
		/* rho + pi */
		{
			uint64_t tmp[25];
			for (int x = 0; x < 5; x++)
				for (int y = 0; y < 5; y++) {
					int nx = y, ny = (2*x + 3*y) % 5;
					tmp[nx + 5*ny] = rol64(s[x + 5*y], ROT[x + 5*y]);
				}
			/* chi */
			for (int y = 0; y < 5; y++)
				for (int x = 0; x < 5; x++)
					s[x + 5*y] = tmp[x + 5*y] ^
						((~tmp[(x+1)%5 + 5*y]) & tmp[(x+2)%5 + 5*y]);
		}
		/* iota */
		s[0] ^= RC[round];
	}
}

static void keccak_absorb_block(os_keccak_ctx *ctx, const uint8_t *block)
{
	for (size_t i = 0; i < RATE_BYTES / 8; i++) {
		uint64_t lane = 0;
		for (int j = 0; j < 8; j++)
			lane |= (uint64_t)block[i*8 + j] << (8 * j);
		ctx->state[i] ^= lane;
	}
	keccak_f(ctx->state);
}

void os_keccak256_init(os_keccak_ctx *ctx)
{
	memset(ctx->state, 0, sizeof ctx->state);
	ctx->buffer_len = 0;
}

void os_keccak256_update(os_keccak_ctx *ctx, const uint8_t *data, size_t len)
{
	while (len > 0) {
		size_t take = RATE_BYTES - ctx->buffer_len;
		if (take > len) take = len;
		memcpy(ctx->buffer + ctx->buffer_len, data, take);
		ctx->buffer_len += take;
		data += take;
		len -= take;
		if (ctx->buffer_len == RATE_BYTES) {
			keccak_absorb_block(ctx, ctx->buffer);
			ctx->buffer_len = 0;
		}
	}
}

void os_keccak256_final(os_keccak_ctx *ctx, uint8_t *out32)
{
	/* Keccak (Ethereum) padding: 0x01 ... 0x80 (NOT SHA3's 0x06) */
	ctx->buffer[ctx->buffer_len++] = 0x01;
	while (ctx->buffer_len < RATE_BYTES)
		ctx->buffer[ctx->buffer_len++] = 0x00;
	ctx->buffer[RATE_BYTES - 1] |= 0x80;
	keccak_absorb_block(ctx, ctx->buffer);

	/* squeeze first 32 bytes (little-endian lanes) */
	for (size_t i = 0; i < 4; i++) {
		uint64_t lane = ctx->state[i];
		for (int j = 0; j < 8; j++)
			out32[i*8 + j] = (uint8_t)(lane >> (8 * j));
	}
}

void os_keccak256(const uint8_t *data, size_t len, uint8_t *out32)
{
	os_keccak_ctx ctx;
	os_keccak256_init(&ctx);
	os_keccak256_update(&ctx, data, len);
	os_keccak256_final(&ctx, out32);
}

void os_eth_address_checksum(const uint8_t addr20[20], char *out43)
{
	static const char *hex = "0123456789abcdef";
	char lower[40];
	uint8_t hash[32];

	for (int i = 0; i < 20; i++) {
		lower[i*2]   = hex[addr20[i] >> 4];
		lower[i*2+1] = hex[addr20[i] & 0xf];
	}
	os_keccak256((const uint8_t *)lower, 40, hash);

	out43[0] = '0'; out43[1] = 'x';
	for (int i = 0; i < 40; i++) {
		char c = lower[i];
		/* EIP-55: uppercase alpha if corresponding hash nibble >= 8 */
		if (c >= 'a' && c <= 'f') {
			uint8_t nib = (i % 2 == 0) ? (hash[i/2] >> 4) : (hash[i/2] & 0xf);
			if (nib >= 8)
				c = c - 'a' + 'A';
		}
		out43[2 + i] = c;
	}
	out43[42] = 0;
}
