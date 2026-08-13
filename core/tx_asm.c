/*
 * HardID Hardware Wallet — host-side transaction assembly
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "tx_asm.h"
#include <string.h>

/* secp256k1 group order n and floor(n/2), big-endian. Public constants
 * (the curve order); the low-s bound is n/2. */
static const uint8_t N_BE[32] = {
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
	0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41
};
static const uint8_t HALF_N_BE[32] = {
	0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0
};

/* compare a 32-byte big-endian scalar against c; returns -1/0/1 */
static int cmp32(const uint8_t *a, const uint8_t *c)
{
	for (int i = 0; i < 32; i++) {
		if (a[i] != c[i]) return a[i] < c[i] ? -1 : 1;
	}
	return 0;
}

/* s = n - s (big-endian 32-byte) — assumes s != 0 */
static void negate32(uint8_t *s)
{
	int borrow = 0;
	for (int i = 31; i >= 0; i--) {
		int d = N_BE[i] - s[i] - borrow;
		if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
		s[i] = (uint8_t)d;
	}
}

int os_evm_sig_assemble(uint32_t chain_id,
                        const uint8_t sig64[64], uint8_t recid,
                        uint8_t *out, size_t out_max, size_t *out_len)
{
	if (!sig64 || !out || !out_len)
		return -1;
	if (recid > 1)
		return -1;

	uint32_t v = 35u + 2u * chain_id + recid;

	/* minimal big-endian encoding of v */
	uint8_t vbe[4];
	int n = 0;
	do {
		vbe[n++] = (uint8_t)(v & 0xFFu);
		v >>= 8;
	} while (v != 0);
	/* vbe holds the little-endian digits; emit big-endian */

	if (64u + (size_t)n > out_max)
		return -1;

	memcpy(out, sig64, 64);
	size_t p = 64;
	for (int i = n - 1; i >= 0; i--)
		out[p++] = vbe[i];
	*out_len = p;
	return 0;
}

int os_btc_sig_to_der(const uint8_t sig64[64], uint8_t sighash_type,
                      uint8_t *out, size_t out_max, size_t *out_len)
{
	if (!sig64 || !out || !out_len)
		return -1;

	uint8_t s[32];
	memcpy(s, sig64 + 32, 32);
	/* BIP62 low-s: if s > n/2 use n - s. */
	if (cmp32(s, HALF_N_BE) > 0)
		negate32(s);

	const uint8_t *r = sig64;

	/* strip leading zeros; if the top bit is set, prepend a 0x00 to keep
	 * the integer positive under DER's signed-integer encoding. */
	int r_off = 0, s_off = 0;
	while (r_off < 32 && r[r_off] == 0) r_off++;
	while (s_off < 32 && s[s_off] == 0) s_off++;
	int r_neg = r_off < 32 && (r[r_off] & 0x80);
	int s_neg = s_off < 32 && (s[s_off] & 0x80);
	size_t rlen = (size_t)(32 - r_off) + (r_neg ? 1 : 0);
	size_t slen = (size_t)(32 - s_off) + (s_neg ? 1 : 0);

	/* content = (0x02 rlen r) | (0x02 slen s) | sighash_type */
	size_t content = (2 + rlen) + (2 + slen) + 1;
	size_t total = 2 + content;             /* 0x30 + len + content */
	if (total > out_max)
		return -1;

	size_t p = 0;
	out[p++] = 0x30;
	out[p++] = (uint8_t)content;            /* sequence length */
	out[p++] = 0x02;
	out[p++] = (uint8_t)rlen;
	if (r_neg) out[p++] = 0x00;
	memcpy(out + p, r + r_off, 32 - (size_t)r_off); p += 32 - (size_t)r_off;
	out[p++] = 0x02;
	out[p++] = (uint8_t)slen;
	if (s_neg) out[p++] = 0x00;
	memcpy(out + p, s + s_off, 32 - (size_t)s_off); p += 32 - (size_t)s_off;
	out[p++] = sighash_type;

	*out_len = p;
	return 0;
}

int os_btc_witness_p2wpkh(const uint8_t sig64[64], uint8_t sighash_type,
                          const uint8_t pub33[33],
                          uint8_t *out, size_t out_max, size_t *out_len)
{
	if (!sig64 || !pub33 || !out || !out_len)
		return -1;

	uint8_t sig[73];
	size_t sig_len = 0;
	if (os_btc_sig_to_der(sig64, sighash_type, sig, sizeof(sig), &sig_len) != 0)
		return -1;

	/* witness stack: <count=2> <len(sig)> sig <len(pub)=33> pub */
	size_t total = 1 + 1 + sig_len + 1 + 33;   /* 109 worst case */
	if (total > out_max)
		return -1;

	size_t p = 0;
	out[p++] = 2;               /* stack item count */
	out[p++] = (uint8_t)sig_len; /* CompactSize: sig_len ≤ 73 fits one byte */
	memcpy(out + p, sig, sig_len); p += sig_len;
	out[p++] = 33;              /* CompactSize: pubkey length */
	memcpy(out + p, pub33, 33); p += 33;

	*out_len = p;
	return 0;
}
