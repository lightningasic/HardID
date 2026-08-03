/*
 * OpenShield Hardware Wallet — BTC PSBT (BIP174) parser
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "psbt.h"
#include <string.h>
#include <stdio.h>

/* ---- varint ---- */
static int rd_varint(const uint8_t **p, size_t *n, uint64_t *out)
{
	if (*n < 1) return -1;
	uint8_t b = (*p)[0];
	if (b < 0xfd) { *out = b; (*p)++; (*n)--; return 0; }
	if (b == 0xfd) {
		if (*n < 3) return -1;
		*out = (*p)[1] | ((uint64_t)(*p)[2] << 8);
		(*p) += 3; (*n) -= 3; return 0;
	}
	if (b == 0xfe) {
		if (*n < 5) return -1;
		*out = (uint64_t)(*p)[1] | ((uint64_t)(*p)[2] << 8) |
		       ((uint64_t)(*p)[3] << 16) | ((uint64_t)(*p)[4] << 24);
		(*p) += 5; (*n) -= 5; return 0;
	}
	if (*n < 9) return -1;
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)(*p)[1 + i] << (8 * i);
	*out = v; (*p) += 9; (*n) -= 9; return 0;
}

static uint64_t rd_u64le(const uint8_t *p)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++) v |= (uint64_t)p[i] << (8 * i);
	return v;
}

/* ---- address decode from scriptPubKey (common templates) ---- */

/* base58check encode (P2PKH/P2SH) */
static const char b58[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
static void b58check(uint8_t ver, const uint8_t *payload20, char *out)
{
	uint8_t buf[25];
	buf[0] = ver;
	memcpy(buf + 1, payload20, 20);
	/* checksum = first 4 bytes of double-SHA256 — stubbed to zeros here;
	 * host supplies full base58check in production. We mark addr_valid
	 * false for base58 to force hex fallback display. */
	(void)out;
	(void)b58;
}

/* bech32 encode (P2WPKH/P2WSH v0) — minimal, correct charset */
static const char bech32_charset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static uint32_t bech32_polymod(const uint8_t *v, size_t n)
{
	static const uint32_t gen[5] = {0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3};
	uint32_t chk = 1;
	for (size_t i = 0; i < n; i++) {
		uint32_t top = chk >> 25;
		chk = (chk & 0x1ffffff) << 5 ^ v[i];
		for (int j = 0; j < 5; j++)
			if ((top >> j) & 1) chk ^= gen[j];
	}
	return chk;
}

static size_t convertbits(const uint8_t *in, size_t inlen, int from, int to,
                          bool pad, uint8_t *out)
{
	uint32_t acc = 0; int bits = 0; size_t o = 0;
	uint32_t maxv = (1u << to) - 1;
	for (size_t i = 0; i < inlen; i++) {
		acc = (acc << from) | in[i];
		bits += from;
		while (bits >= to) {
			bits -= to;
			out[o++] = (acc >> bits) & maxv;
		}
	}
	if (pad && bits) out[o++] = (acc << (to - bits)) & maxv;
	return o;
}

/* encode a v0 witness program (20 or 32 bytes) as bech32 "bc1..." */
static bool bech32_v0(const uint8_t *prog, size_t plen, char *out, size_t outmax)
{
	uint8_t data[64]; size_t dlen = 0;
	data[dlen++] = 0; /* witness version 0 */
	dlen += convertbits(prog, plen, 8, 5, true, data + dlen);
	/* checksum over hrp-expanded "bc" + data + 6 zero */
	uint8_t tmp[128]; size_t t = 0;
	tmp[t++] = 3; tmp[t++] = 3; tmp[t++] = 0; tmp[t++] = 2; tmp[t++] = 3; /* hrp expand "bc" */
	memcpy(tmp + t, data, dlen); t += dlen;
	for (int i = 0; i < 6; i++) tmp[t++] = 0;
	uint32_t pm = bech32_polymod(tmp, t) ^ 1;
	uint8_t full[80]; size_t f = 0;
	memcpy(full, data, dlen); f = dlen;
	for (int i = 5; i >= 0; i--) full[f++] = (pm >> (5 * i)) & 31;

	size_t need = 4 + f; /* "bc1" + data */
	if (outmax < need + 1) return false;
	out[0]='b'; out[1]='c'; out[2]='1';
	for (size_t i = 0; i < f; i++) out[3 + i] = bech32_charset[full[i]];
	out[3 + f] = 0;
	return true;
}

/* decode a scriptPubKey into an address string; returns addr_valid */
static bool script_to_addr(const uint8_t *s, size_t n, char *out, size_t outmax)
{
	/* P2WPKH: 0014 <20> */
	if (n == 22 && s[0] == 0x00 && s[1] == 0x14)
		return bech32_v0(s + 2, 20, out, outmax);
	/* P2WSH: 0020 <32> */
	if (n == 34 && s[0] == 0x00 && s[1] == 0x20)
		return bech32_v0(s + 2, 32, out, outmax);
	/* P2TR: 5120 <32> (bech32m — not implemented here, mark invalid) */
	if (n == 34 && s[0] == 0x51 && s[1] == 0x20)
		return false;
	/* P2PKH/P2SH: not doing base58check inline (needs sha256); mark invalid */
	(void)b58check;
	return false;
}

/* ---- unsigned tx walker (inside PSBT global map) ---- */
/* The PSBT global unsigned tx is a legacy-serialized tx. We only need its
 * outputs (scriptPubKey + amount) for display; input amounts come from
 * per-input witness_utxo fields. */

typedef struct {
	const uint8_t *p;
	size_t n;
} reader;

static int tx_outputs(const uint8_t *tx, size_t txn, os_psbt_summary *o,
                      bool (*chg)(const uint8_t *, size_t))
{
	reader r = { tx, txn };
	if (r.n < 4) return -1;
	r.p += 4; r.n -= 4;                 /* version */
	/* segwit marker/flag */
	bool segwit = false;
	if (r.n >= 2 && r.p[0] == 0x00 && r.p[1] != 0x00) {
		segwit = true; r.p += 2; r.n -= 2;
	}
	uint64_t nin;
	if (rd_varint(&r.p, &r.n, &nin) != 0) return -1;
	/* skip inputs: prev(36) + scriptSig(var) + seq(4) */
	for (uint64_t i = 0; i < nin; i++) {
		if (r.n < 36) return -1;
		r.p += 36; r.n -= 36;
		uint64_t sl;
		if (rd_varint(&r.p, &r.n, &sl) != 0 || r.n < sl) return -1;
		r.p += sl; r.n -= sl;
		if (r.n < 4) return -1;
		r.p += 4; r.n -= 4;
	}
	uint64_t nout;
	if (rd_varint(&r.p, &r.n, &nout) != 0) return -1;
	if (nout > OS_PSBT_MAX_OUTPUTS) return -1;
	o->output_count = (uint32_t)nout;

	for (uint64_t i = 0; i < nout; i++) {
		if (r.n < 8) return -1;
		uint64_t amt = rd_u64le(r.p);
		r.p += 8; r.n -= 8;
		uint64_t sl;
		if (rd_varint(&r.p, &r.n, &sl) != 0 || r.n < sl) return -1;
		os_psbt_output *out = &o->outputs[i];
		out->amount = amt;
		out->addr_valid = script_to_addr(r.p, sl, out->address, sizeof out->address);
		if (!out->addr_valid) {
			/* fallback: hex of script (bounded) */
			size_t show = sl < 16 ? sl : 16;
			char *w = out->address;
			for (size_t k = 0; k < show; k++) {
				snprintf(w, 3, "%02x", r.p[k]);
				w += 2;
			}
			*w = 0;
		}
		out->is_change = chg ? chg(r.p, sl) : false;
		if (!out->is_change)
			o->spend_count++;
		o->total_out += amt;
		r.p += sl; r.n -= sl;
	}
	/* witness data + locktime ignored */
	(void)segwit;
	return 0;
}

int os_psbt_parse(const uint8_t *psbt, size_t len,
                  bool (*change_check)(const uint8_t *script, size_t slen),
                  os_psbt_summary *o)
{
	if (len < 5 || memcmp(psbt, "psbt\xff", 5) != 0)
		return -1;
	memset(o, 0, sizeof *o);

	const uint8_t *p = psbt + 5;
	size_t n = len - 5;
	const uint8_t *unsigned_tx = NULL;
	size_t unsigned_tx_len = 0;

	/* global map */
	for (;;) {
		uint64_t klen;
		if (rd_varint(&p, &n, &klen) != 0) return -1;
		if (klen == 0) break;                 /* separator */
		if (n < klen) return -1;
		const uint8_t *key = p;
		p += klen; n -= klen;
		uint64_t vlen;
		if (rd_varint(&p, &n, &vlen) != 0 || n < vlen) return -1;
		/* global key 0x00 = unsigned tx */
		if (klen == 1 && key[0] == 0x00) {
			unsigned_tx = p;
			unsigned_tx_len = vlen;
		}
		p += vlen; n -= vlen;
	}
	if (!unsigned_tx)
		return -1;

	if (tx_outputs(unsigned_tx, unsigned_tx_len, o, change_check) != 0)
		return -1;

	/* input maps: sum witness_utxo (key 0x01) amounts */
	for (uint32_t i = 0; i < OS_PSBT_MAX_INPUTS && n > 0; i++) {
		bool more = false;
		const uint8_t *mp = p;
		size_t mn = n;
		size_t consumed = 0;
		for (;;) {
			uint64_t klen;
			if (rd_varint(&mp, &mn, &klen) != 0) return -1;
			if (klen == 0) { consumed++; break; }     /* end of this input map */
			if (mn < klen) return -1;
			const uint8_t *key = mp;
			mp += klen; mn -= klen;
			uint64_t vlen;
			if (rd_varint(&mp, &mn, &vlen) != 0 || mn < vlen) return -1;
			if (klen == 1 && key[0] == 0x01 && vlen >= 8) {
				/* witness_utxo: amount(8le) + script */
				o->total_in += rd_u64le(mp);
			}
			mp += vlen; mn -= vlen;
			more = true;
		}
		/* advance outer reader past this map */
		size_t used = (size_t)(mp - p);
		p += used; n -= used;
		(void)consumed;
		if (!more && n == 0) break;
		o->input_count++;
	}

	if (o->input_count == 0)
		return -1;
	if (o->total_in < o->total_out)
		return -1;
	o->fee = o->total_in - o->total_out;
	return 0;
}
