/*
 * OpenShield Hardware Wallet — BIP32 HD key derivation
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "bip32.h"
#include "secp256k1.h"
#include "sha512.h"
#include "sha256.h"
#include "base58.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* HASH160 = RIPEMD160(SHA256(x)). We need RIPEMD-160 for fingerprint and
 * addresses. Implement a compact RIPEMD-160 here. */

/* ---- RIPEMD-160 (compact, public-domain-style clean-room) ---- */
typedef struct {
	uint32_t h[5];
	uint64_t len;
	uint8_t buf[64];
	size_t buflen;
} rmd160_ctx;

static uint32_t rol32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static const uint8_t R1[80] = {
	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
	3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
	4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
static const uint8_t R2[80] = {
	5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
	15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
	12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
static const uint8_t S1[80] = {
	11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
	11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
	9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
static const uint8_t S2[80] = {
	8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
	9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
	8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };

static uint32_t f1(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t f2(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t f3(uint32_t x, uint32_t y, uint32_t z) { return (x | ~y) ^ z; }
static uint32_t f4(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t f5(uint32_t x, uint32_t y, uint32_t z) { return x ^ (y | ~z); }

static void rmd160_block(rmd160_ctx *c, const uint8_t *p)
{
	uint32_t X[16];
	for (int i = 0; i < 16; i++)
		X[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
		       ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);

	uint32_t al = c->h[0], bl = c->h[1], cl = c->h[2], dl = c->h[3], el = c->h[4];
	uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;

	for (int j = 0; j < 80; j++) {
		uint32_t tl, tr;
		int r = j / 16;
		if (r == 0)      tl = rol32(al + f1(bl, cl, dl) + X[R1[j]] + 0x00000000, S1[j]);
		else if (r == 1) tl = rol32(al + f2(bl, cl, dl) + X[R1[j]] + 0x5A827999, S1[j]);
		else if (r == 2) tl = rol32(al + f3(bl, cl, dl) + X[R1[j]] + 0x6ED9EBA1, S1[j]);
		else if (r == 3) tl = rol32(al + f4(bl, cl, dl) + X[R1[j]] + 0x8F1BBCDC, S1[j]);
		else             tl = rol32(al + f5(bl, cl, dl) + X[R1[j]] + 0xA953FD4E, S1[j]);
		tl += el;
		al = el; el = dl; dl = rol32(cl, 10); cl = bl; bl = tl;

		if (r == 0)      tr = rol32(ar + f5(br, cr, dr) + X[R2[j]] + 0x50A28BE6, S2[j]);
		else if (r == 1) tr = rol32(ar + f4(br, cr, dr) + X[R2[j]] + 0x5C4DD124, S2[j]);
		else if (r == 2) tr = rol32(ar + f3(br, cr, dr) + X[R2[j]] + 0x6D703EF3, S2[j]);
		else if (r == 3) tr = rol32(ar + f2(br, cr, dr) + X[R2[j]] + 0x7A6D76E9, S2[j]);
		else             tr = rol32(ar + f1(br, cr, dr) + X[R2[j]] + 0x00000000, S2[j]);
		tr += er;
		ar = er; er = dr; dr = rol32(cr, 10); cr = br; br = tr;
	}

	uint32_t t = c->h[1] + cl + dr;
	c->h[1] = c->h[2] + dl + er;
	c->h[2] = c->h[3] + el + ar;
	c->h[3] = c->h[4] + al + br;
	c->h[4] = c->h[0] + bl + cr;
	c->h[0] = t;
}

static void rmd160_init(rmd160_ctx *c)
{
	c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
	c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0;
	c->len = 0; c->buflen = 0;
}

static void rmd160_update(rmd160_ctx *c, const uint8_t *d, size_t n)
{
	c->len += n;
	while (n) {
		size_t take = 64 - c->buflen;
		if (take > n) take = n;
		memcpy(c->buf + c->buflen, d, take);
		c->buflen += take; d += take; n -= take;
		if (c->buflen == 64) {
			rmd160_block(c, c->buf);
			c->buflen = 0;
		}
	}
}

static void rmd160_final(rmd160_ctx *c, uint8_t *out20)
{
	uint64_t bits = c->len * 8;
	uint8_t pad = 0x80;
	rmd160_update(c, &pad, 1);
	uint8_t z = 0;
	while (c->buflen != 56)
		rmd160_update(c, &z, 1);
	uint8_t lenb[8];
	for (int i = 0; i < 8; i++) lenb[i] = (uint8_t)(bits >> (8 * i));
	rmd160_update(c, lenb, 8);
	for (int i = 0; i < 5; i++)
		for (int j = 0; j < 4; j++)
			out20[i*4 + j] = (uint8_t)(c->h[i] >> (8 * j));
}

static void hash160(const uint8_t *in, size_t n, uint8_t *out20)
{
	uint8_t sh[32];
	os_sha256(in, n, sh);
	rmd160_ctx c;
	rmd160_init(&c);
	rmd160_update(&c, sh, 32);
	rmd160_final(&c, out20);
}

/* ---- BIP32 ---- */

static const char MASTER_KEY[] = "Bitcoin seed";

int os_bip32_from_seed(const uint8_t *seed, size_t seed_len, os_hdnode *node)
{
	uint8_t I[64];
	os_hmac_sha512((const uint8_t *)MASTER_KEY, sizeof(MASTER_KEY) - 1,
	               seed, seed_len, I);
	memcpy(node->priv, I, 32);
	memcpy(node->chain_code, I + 32, 32);
	node->depth = 0;
	node->fingerprint = 0;
	node->child_num = 0;
	node->has_priv = true;
	memset(I, 0, sizeof I);
	if (os_secp256k1_pubkey(node->priv, node->pub) != 0)
		return -1;
	return 0;
}

uint32_t os_bip32_fingerprint(const os_hdnode *node)
{
	uint8_t h[20];
	hash160(node->pub, 33, h);
	/* big-endian: first 4 bytes of HASH160 in display order */
	return ((uint32_t)h[0] << 24) | ((uint32_t)h[1] << 16) |
	       ((uint32_t)h[2] << 8) | (uint32_t)h[3];
}

int os_bip32_ckd(const os_hdnode *parent, uint32_t index, os_hdnode *child)
{
	uint8_t I[64];
	os_hmac_sha512_ctx h;
	os_hmac_sha512_init(&h, parent->chain_code, 32);

	uint8_t idxbe[4] = {
		(uint8_t)(index >> 24), (uint8_t)(index >> 16),
		(uint8_t)(index >> 8), (uint8_t)index };

	if (index & 0x80000000u) {
		/* hardened: 0x00 || priv || index */
		if (!parent->has_priv) { memset(I,0,64); return -1; }
		uint8_t z = 0;
		os_hmac_sha512_update(&h, &z, 1);
		os_hmac_sha512_update(&h, parent->priv, 32);
		os_hmac_sha512_update(&h, idxbe, 4);
	} else {
		/* normal: pub || index */
		os_hmac_sha512_update(&h, parent->pub, 33);
		os_hmac_sha512_update(&h, idxbe, 4);
	}
	os_hmac_sha512_final(&h, I);

	/* Public-only CKD (point add) not implemented: OpenShield derives on
	 * the SE which always holds privkey. Require private parent. */
	if (!parent->has_priv) {
		memset(I, 0, 64);
		return -1;
	}

	/* child priv = (IL + parent.priv) mod n, big-endian. */
	static const uint8_t NBE[32] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
		0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
	uint16_t carry = 0;
	uint8_t sum[32];
	for (int i = 31; i >= 0; i--) {
		uint16_t s = (uint16_t)I[i] + parent->priv[i] + carry;
		sum[i] = (uint8_t)s;
		carry = s >> 8;
	}
	/* IL, parent < n  =>  sum < 2n, so at most one subtraction of n.
	 * subtract when carry=1 (sum >= 2^256 > n) or sum >= n. */
	{
		int ge = carry ? 1 : 0;
		if (!ge) {
			for (int i = 0; i < 32; i++) {
				if (sum[i] != NBE[i]) { ge = (sum[i] > NBE[i]); break; }
			}
		}
		if (ge) {
			uint16_t borrow = 0;
			for (int i = 31; i >= 0; i--) {
				int d = sum[i] - NBE[i] - borrow;
				if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
				sum[i] = (uint8_t)d;
			}
		}
	}
	memcpy(child->priv, sum, 32);
	child->has_priv = true;
	if (os_secp256k1_pubkey(child->priv, child->pub) != 0) {
		memset(I, 0, 64);
		return -1;
	}

	memcpy(child->chain_code, I + 32, 32);
	child->depth = parent->depth + 1;
	child->fingerprint = os_bip32_fingerprint(parent);
	child->child_num = index;
	memset(I, 0, sizeof I);
	return 0;
}

int os_bip32_derive_path(os_hdnode *node, const char *path)
{
	/* path like "m/44'/0'/0'/0/0" — mutate node in place */
	if (!path || path[0] != 'm')
		return -1;
	const char *p = path + 1;
	while (*p) {
		if (*p != '/') return -1;
		p++;
		char *end;
		unsigned long v = strtoul(p, &end, 10);
		if (end == p) return -1;
		uint32_t idx = (uint32_t)v;
		if (*end == '\'') { idx |= 0x80000000u; end++; }
		os_hdnode child;
		if (os_bip32_ckd(node, idx, &child) != 0)
			return -1;
		*node = child;
		p = end;
	}
	return 0;
}

size_t os_bip32_serialize(const os_hdnode *node, bool private,
                          uint32_t version, char *out, size_t outmax)
{
	uint8_t data[78];
	data[0] = (uint8_t)(version >> 24);
	data[1] = (uint8_t)(version >> 16);
	data[2] = (uint8_t)(version >> 8);
	data[3] = (uint8_t)version;
	data[4] = node->depth;
	data[5] = (uint8_t)(node->fingerprint >> 24);
	data[6] = (uint8_t)(node->fingerprint >> 16);
	data[7] = (uint8_t)(node->fingerprint >> 8);
	data[8] = (uint8_t)(node->fingerprint);
	data[9]  = (uint8_t)(node->child_num >> 24);
	data[10] = (uint8_t)(node->child_num >> 16);
	data[11] = (uint8_t)(node->child_num >> 8);
	data[12] = (uint8_t)(node->child_num);
	memcpy(data + 13, node->chain_code, 32);
	if (private) {
		if (!node->has_priv) return 0;
		data[45] = 0;
		memcpy(data + 46, node->priv, 32);
	} else {
		memcpy(data + 45, node->pub, 33);
	}
	return os_base58_encode_check(data, 78, out, outmax);
}
