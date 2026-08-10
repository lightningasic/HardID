/*
 * HardID Hardware Wallet — BTC PSBT (BIP174) parser
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "psbt.h"
#include "base58.h"
#include "sha256.h"
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

/* encode a v0 witness program (20 or 32 bytes) as bech32 "bc1..." */
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

/* encode a v0 witness program (20 or 32 bytes) as bech32 "<hrp>1..." */
static bool bech32_v0_hrp(const uint8_t *prog, size_t plen, const char *hrp,
                          char *out, size_t outmax)
{
	uint8_t data[64]; size_t dlen = 0;
	data[dlen++] = 0; /* witness version 0 */
	dlen += convertbits(prog, plen, 8, 5, true, data + dlen);
	/* checksum over hrp-expanded hrp + data + 6 zero */
	uint8_t tmp[128]; size_t t = 0;
	size_t hl = strlen(hrp);
	for (size_t i = 0; i < hl; i++) tmp[t++] = (uint8_t)(hrp[i] >> 5);
	tmp[t++] = 0;
	for (size_t i = 0; i < hl; i++) tmp[t++] = (uint8_t)(hrp[i] & 31);
	memcpy(tmp + t, data, dlen); t += dlen;
	for (int i = 0; i < 6; i++) tmp[t++] = 0;
	uint32_t pm = bech32_polymod(tmp, t) ^ 1;
	uint8_t full[80]; size_t f = 0;
	memcpy(full, data, dlen); f = dlen;
	for (int i = 5; i >= 0; i--) full[f++] = (pm >> (5 * i)) & 31;

	size_t need = hl + 1 + f; /* hrp + '1' + data */
	if (outmax < need + 1) return false;
	memcpy(out, hrp, hl);
	out[hl] = '1';
	for (size_t i = 0; i < f; i++) out[hl + 1 + i] = bech32_charset[full[i]];
	out[hl + 1 + f] = 0;
	return true;
}

/* Per-coin address encoding parameters (BIP44 coin_type keyed).
 * segwit_hrp NULL means the chain has no deployed segwit encoding — a
 * segwit output script then renders as hex (addr_valid=false), never as a
 * wrong-chain address. BCH note: legacy base58 is shown (0x00/0x05, same
 * as BTC); cashaddr is a follow-up. */
typedef struct {
	const char *segwit_hrp;  /* bech32 HRP for v0 witness programs */
	uint8_t     p2pkh_ver;   /* base58check version byte */
	uint8_t     p2sh_ver;
} os_btc_addr_params;

static bool btc_addr_params(uint32_t coin_type, os_btc_addr_params *p)
{
	switch (coin_type) {
	case 0:   *p = (os_btc_addr_params){ "bc",  0x00, 0x05 }; return true;
	case 2:   *p = (os_btc_addr_params){ "ltc", 0x30, 0x32 }; return true;
	case 3:   *p = (os_btc_addr_params){ NULL,  0x1e, 0x16 }; return true; /* DOGE: no segwit */
	case 145: *p = (os_btc_addr_params){ NULL,  0x00, 0x05 }; return true; /* BCH: legacy base58 */
	default:  return false;
	}
}

/* decode a scriptPubKey into an address string for `coin_type`;
 * returns addr_valid */
static bool script_to_addr(const uint8_t *s, size_t n, uint32_t coin_type,
                           char *out, size_t outmax)
{
	os_btc_addr_params p = { NULL, 0, 0 };
	bool have = btc_addr_params(coin_type, &p);
	/* P2WPKH: 0014 <20> */
	if (n == 22 && s[0] == 0x00 && s[1] == 0x14)
		return have && p.segwit_hrp &&
		       bech32_v0_hrp(s + 2, 20, p.segwit_hrp, out, outmax);
	/* P2WSH: 0020 <32> */
	if (n == 34 && s[0] == 0x00 && s[1] == 0x20)
		return have && p.segwit_hrp &&
		       bech32_v0_hrp(s + 2, 32, p.segwit_hrp, out, outmax);
	/* P2TR: 5120 <32> (bech32m — not implemented here, mark invalid) */
	if (n == 34 && s[0] == 0x51 && s[1] == 0x20)
		return false;
	/* P2PKH: 76a914 <20> 88ac */
	if (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
	    s[23] == 0x88 && s[24] == 0xac)
		return have && os_base58check_encode(p.p2pkh_ver, s + 3, out, outmax) != 0;
	/* P2SH: a914 <20> 87 */
	if (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87)
		return have && os_base58check_encode(p.p2sh_ver, s + 2, out, outmax) != 0;
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
                      bool (*chg)(const uint8_t *, size_t),
                      uint32_t coin_type, uint32_t *nin_out)
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
	if (nin > OS_PSBT_MAX_INPUTS) return -1;
	*nin_out = (uint32_t)nin;
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
		out->addr_valid = script_to_addr(r.p, sl, coin_type,
		                                 out->address, sizeof out->address);
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
		if (amt > UINT64_MAX - o->total_out) return -1;  /* overflow guard */
		o->total_out += amt;
		r.p += sl; r.n -= sl;
	}
	/* witness data + locktime ignored */
	(void)segwit;
	return 0;
}

int os_psbt_parse(const uint8_t *psbt, size_t len,
                  bool (*change_check)(const uint8_t *script, size_t slen),
                  uint32_t coin_type,
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

	uint32_t nin = 0;
	if (tx_outputs(unsigned_tx, unsigned_tx_len, o, change_check,
	               coin_type, &nin) != 0)
		return -1;

	/* input maps: exactly nin maps follow the global map (BIP174 order).
	 * Reading beyond nin would misparse OUTPUT maps as input maps — and
	 * output key 0x01 (witness_script) collides with input key 0x01
	 * (witness_utxo), corrupting total_in / fee. */
	for (uint32_t i = 0; i < nin; i++) {
		if (n == 0) return -1;
		const uint8_t *mp = p;
		size_t mn = n;
		size_t consumed = 0;
		bool seen_witness_utxo = false;
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
				/* duplicate witness_utxo would double-count total_in and
				 * fake the fee — reject a repeated key within one map. */
				if (seen_witness_utxo) return -1;
				seen_witness_utxo = true;
				uint64_t a = rd_u64le(mp);
				if (a > UINT64_MAX - o->total_in) return -1;  /* overflow */
				o->total_in += a;
			}
			mp += vlen; mn -= vlen;
		}
		/* advance outer reader past this map */
		size_t used = (size_t)(mp - p);
		p += used; n -= used;
		(void)consumed;
		o->input_count++;
	}

	if (o->input_count == 0)
		return -1;
	if (o->total_in < o->total_out)
		return -1;
	o->fee = o->total_in - o->total_out;
	return 0;
}

/* ------------------------------------------------------------------ *
 * BIP143 sighash (M-2): the REAL chain-bound digest for BTC-family
 * signing. Only native P2WPKH inputs and SIGHASH_ALL are supported —
 * anything else is refused, never guessed.
 * ------------------------------------------------------------------ */

static void dsha256(const uint8_t *d, size_t n, uint8_t out[32])
{
	uint8_t t[32];
	os_sha256(d, n, t);
	os_sha256(t, sizeof t, out);
}

/* Walk a legacy-serialized unsigned tx, capturing everything BIP143
 * needs. Returns 0 / -1. Buffers are bounded by OS_PSBT_MAX_INPUTS and
 * OS_PSBT_MAX_OUTPUTS. */
static int tx_walk_full(const uint8_t *tx, size_t txn,
                        uint8_t (*outpoints)[36], uint8_t (*seqs)[4],
                        uint32_t *nin,
                        uint8_t (*outs)[8 + 3 + 128], size_t *out_lens,
                        uint32_t *nout,
                        uint8_t version[4], uint8_t locktime[4])
{
	reader r = { tx, txn };
	if (r.n < 4) return -1;
	memcpy(version, r.p, 4);
	r.p += 4; r.n -= 4;
	if (r.n >= 2 && r.p[0] == 0x00 && r.p[1] != 0x00) {
		r.p += 2; r.n -= 2;   /* segwit marker/flag (no witnesses in PSBT) */
	}
	uint64_t ni;
	if (rd_varint(&r.p, &r.n, &ni) != 0) return -1;
	if (ni == 0 || ni > OS_PSBT_MAX_INPUTS) return -1;
	*nin = (uint32_t)ni;
	for (uint64_t i = 0; i < ni; i++) {
		if (r.n < 36) return -1;
		memcpy(outpoints[i], r.p, 36);       /* prev txid + vout */
		r.p += 36; r.n -= 36;
		uint64_t sl;
		if (rd_varint(&r.p, &r.n, &sl) != 0 || r.n < sl) return -1;
		r.p += sl; r.n -= sl;                /* scriptSig (ignored) */
		if (r.n < 4) return -1;
		memcpy(seqs[i], r.p, 4);
		r.p += 4; r.n -= 4;
	}
	uint64_t no;
	if (rd_varint(&r.p, &r.n, &no) != 0) return -1;
	if (no > OS_PSBT_MAX_OUTPUTS) return -1;
	*nout = (uint32_t)no;
	for (uint64_t i = 0; i < no; i++) {
		if (r.n < 8) return -1;
		uint64_t sl;
		const uint8_t *amt_p = r.p;
		r.p += 8; r.n -= 8;
		if (rd_varint(&r.p, &r.n, &sl) != 0 || r.n < sl) return -1;
		/* capture the raw output span: amount(8) || varint || script */
		size_t span = 8 + (size_t)(r.p - amt_p - 8) + sl;
		/* outputs are HASHED, not displayed one-by-one here, so the
		 * cap is a memory bound, not a policy: 128-byte scripts cover
		 * every standard form incl. 80-byte OP_RETURN. Larger is
		 * refused (never silently mis-hashed). */
		if (span > 8 + 3 + 128) return -1;
		memcpy(outs[i], amt_p, span);
		out_lens[i] = span;
		r.p += sl; r.n -= sl;
	}
	if (r.n < 4) return -1;
	memcpy(locktime, r.p, 4);
	return 0;
}

int os_btc_bip143_sighash_tx(const uint8_t *tx, size_t tx_len,
                             uint32_t input_index,
                             const uint8_t *witness_spk, size_t spk_len,
                             uint64_t amount_sats,
                             uint32_t sighash_type,
                             uint8_t out32[32])
{
	if (!tx || !out32)
		return -1;
	if (sighash_type != 1)
		return -1;   /* SIGHASH_ALL only: SINGLE/NONE/ANYONECANPAY have
		              * well-known footguns on a hardware signer */
	/* native P2WPKH only: scriptPubKey 0014{20} -> scriptCode
	 * 1976a914{20}88ac */
	if (!witness_spk || spk_len != 22 ||
	    witness_spk[0] != 0x00 || witness_spk[1] != 0x14)
		return -1;

	static uint8_t outpoints[OS_PSBT_MAX_INPUTS][36];
	static uint8_t seqs[OS_PSBT_MAX_INPUTS][4];
	static uint8_t outs[OS_PSBT_MAX_OUTPUTS][8 + 3 + 128];
	static size_t  out_lens[OS_PSBT_MAX_OUTPUTS];
	uint8_t version[4], locktime[4];
	uint32_t nin = 0, nout = 0;
	if (tx_walk_full(tx, tx_len, outpoints, seqs, &nin,
	                 outs, out_lens, &nout, version, locktime) != 0)
		return -1;
	if (input_index >= nin)
		return -1;

	/* hashPrevouts / hashSequence / hashOutputs (SIGHASH_ALL forms) */
	uint8_t hp[32], hs[32], ho[32];
	{
		uint8_t buf[OS_PSBT_MAX_INPUTS * 36];
		size_t n = 0;
		for (uint32_t i = 0; i < nin; i++) {
			memcpy(buf + n, outpoints[i], 36); n += 36;
		}
		dsha256(buf, n, hp);
	}
	{
		uint8_t buf[OS_PSBT_MAX_INPUTS * 4];
		size_t n = 0;
		for (uint32_t i = 0; i < nin; i++) {
			memcpy(buf + n, seqs[i], 4); n += 4;
		}
		dsha256(buf, n, hs);
	}
	{
		static uint8_t buf[OS_PSBT_MAX_OUTPUTS * (8 + 3 + 128)];
		size_t n = 0;
		for (uint32_t i = 0; i < nout; i++) {
			memcpy(buf + n, outs[i], out_lens[i]); n += out_lens[i];
		}
		dsha256(buf, n, ho);
	}

	/* preimage: version || hP || hS || outpoint || scriptCode || amount ||
	 *           nSequence || hO || locktime || sighashType */
	uint8_t pre[4 + 32 + 32 + 36 + 26 + 8 + 4 + 32 + 4 + 4];
	size_t n = 0;
	memcpy(pre + n, version, 4); n += 4;
	memcpy(pre + n, hp, 32); n += 32;
	memcpy(pre + n, hs, 32); n += 32;
	memcpy(pre + n, outpoints[input_index], 36); n += 36;
	pre[n++] = 0x19;                          /* scriptCode length (25) */
	pre[n++] = 0x76; pre[n++] = 0xa9; pre[n++] = 0x14;
	memcpy(pre + n, witness_spk + 2, 20); n += 20;
	pre[n++] = 0x88; pre[n++] = 0xac;
	for (int i = 0; i < 8; i++)
		pre[n++] = (uint8_t)(amount_sats >> (8 * i));
	memcpy(pre + n, seqs[input_index], 4); n += 4;
	memcpy(pre + n, ho, 32); n += 32;
	memcpy(pre + n, locktime, 4); n += 4;
	pre[n++] = 0x01; pre[n++] = 0x00; pre[n++] = 0x00; pre[n++] = 0x00;

	dsha256(pre, n, out32);
	return 0;
}

int os_btc_sighash_from_psbt(const uint8_t *psbt, size_t len,
                             uint32_t input_index, uint8_t out32[32])
{
	if (!psbt || len < 5 || memcmp(psbt, "psbt\xff", 5) != 0)
		return -1;
	const uint8_t *p = psbt + 5;
	size_t n = len - 5;
	const uint8_t *unsigned_tx = NULL;
	size_t unsigned_tx_len = 0;

	/* global map */
	for (;;) {
		uint64_t klen;
		if (rd_varint(&p, &n, &klen) != 0) return -1;
		if (klen == 0) break;
		if (n < klen) return -1;
		const uint8_t *key = p;
		p += klen; n -= klen;
		uint64_t vlen;
		if (rd_varint(&p, &n, &vlen) != 0 || n < vlen) return -1;
		if (klen == 1 && key[0] == 0x00) {
			unsigned_tx = p;
			unsigned_tx_len = vlen;
		}
		p += vlen; n -= vlen;
	}
	if (!unsigned_tx)
		return -1;

	/* walk input maps to input_index; capture witness_utxo + sighash */
	for (uint32_t i = 0; i <= input_index; i++) {
		const uint8_t *wutxo = NULL;
		size_t wutxo_len = 0;
		uint32_t sht = 1;             /* PSBT default: SIGHASH_ALL */
		int saw_witness = 0;
		for (;;) {
			uint64_t klen;
			if (rd_varint(&p, &n, &klen) != 0) return -1;
			if (klen == 0) break;              /* end of this input map */
			if (n < klen) return -1;
			const uint8_t *key = p;
			p += klen; n -= klen;
			uint64_t vlen;
			if (rd_varint(&p, &n, &vlen) != 0 || n < vlen) return -1;
			if (i == input_index && klen == 1 && key[0] == 0x01) {
				wutxo = p; wutxo_len = vlen; saw_witness = 1;
			}
			if (i == input_index && klen == 1 && key[0] == 0x03 &&
			    vlen == 4) {
				sht = (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
				      ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
			}
			p += vlen; n -= vlen;
		}
		if (i == input_index) {
			if (!saw_witness || wutxo_len < 8 + 1)
				return -1;   /* non_witness_utxo inputs unsupported */
			uint64_t amount = rd_u64le(wutxo);
			const uint8_t *sp = wutxo + 8;
			size_t sn = wutxo_len - 8;
			uint64_t slen;
			if (rd_varint(&sp, &sn, &slen) != 0 || sn != slen)
				return -1;
			return os_btc_bip143_sighash_tx(unsigned_tx, unsigned_tx_len,
			                                input_index, sp, slen,
			                                amount, sht, out32);
		}
	}
	return -1;   /* fewer input maps than requested index */
}

int os_btc_psbt_input_count(const uint8_t *psbt, size_t len)
{
	if (!psbt || len < 5 || memcmp(psbt, "psbt\xff", 5) != 0)
		return -1;
	const uint8_t *p = psbt + 5;
	size_t n = len - 5;
	const uint8_t *unsigned_tx = NULL;
	size_t unsigned_tx_len = 0;
	for (;;) {
		uint64_t klen;
		if (rd_varint(&p, &n, &klen) != 0) return -1;
		if (klen == 0) break;
		if (n < klen) return -1;
		const uint8_t *key = p;
		p += klen; n -= klen;
		uint64_t vlen;
		if (rd_varint(&p, &n, &vlen) != 0 || n < vlen) return -1;
		if (klen == 1 && key[0] == 0x00) {
			unsigned_tx = p;
			unsigned_tx_len = vlen;
		}
		p += vlen; n -= vlen;
	}
	if (!unsigned_tx)
		return -1;
	reader r = { unsigned_tx, unsigned_tx_len };
	if (r.n < 4) return -1;
	r.p += 4; r.n -= 4;
	if (r.n >= 2 && r.p[0] == 0x00 && r.p[1] != 0x00) {
		r.p += 2; r.n -= 2;
	}
	uint64_t ni;
	if (rd_varint(&r.p, &r.n, &ni) != 0) return -1;
	if (ni == 0 || ni > OS_PSBT_MAX_INPUTS) return -1;
	return (int)ni;
}
