/* Host-side test of the link service: structured SIGN routed through signsvc.
 * Mirrors test_app.c's setup: real mock SE + app registry + sign delegation.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/se_driver.h"

#include "../core/se_mock.c"
#include "../core/sha512.c"
#include "../core/secp256r1.c"
#include "../core/rfc6979.c"
#include "../core/app_registry.c"
#include "../core/app_catalog.c"
#include "../core/signsvc.c"
#include "../core/keccak.c"
#include "../core/clearsign.c"
#include "../core/psbt.c"
#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/linkproto.c"
#include "../core/linksvc.c"

/* ---- RLP helpers (same as test_app/test_clearsign) ---- */
static size_t rlp_hdr(uint8_t *out, int is_list, size_t l)
{
	uint8_t base = is_list ? 0xc0 : 0x80;
	if (l < 56) { out[0] = base + l; return 1; }
	if (l < 256) { out[0] = base + 55 + 1; out[1] = l; return 2; }
	out[0] = base + 55 + 2; out[1] = l >> 8; out[2] = l & 0xff; return 3;
}
static size_t rlp_str(uint8_t *out, const uint8_t *d, size_t l)
{
	size_t h = rlp_hdr(out, 0, l);
	memcpy(out + h, d, l);
	return h + l;
}
static size_t rlp_u(uint8_t *out, uint64_t v)
{
	uint8_t b[8]; int n = 0;
	if (v == 0) { out[0] = 0x80; return 1; }
	if (v < 0x80) { out[0] = (uint8_t)v; return 1; }
	while (v) { b[7 - n++] = v & 0xff; v >>= 8; }
	return rlp_str(out, b + 8 - n, n);
}
static size_t build_legacy(uint8_t *out, uint64_t gasPrice, uint64_t gasLimit,
                           const uint8_t to[20], uint64_t value)
{
	uint8_t tmp[1024]; size_t o = 0;
	o += rlp_u(tmp + o, 1);
	o += rlp_u(tmp + o, gasPrice);
	o += rlp_u(tmp + o, gasLimit);
	if (to) o += rlp_str(tmp + o, to, 20); else { tmp[o++] = 0x80; }
	o += rlp_u(tmp + o, value);
	o += rlp_str(tmp + o, NULL, 0);
	size_t h = rlp_hdr(out, 1, o);
	memcpy(out + h, tmp, o);
	return h + o;
}

/* ---- UI confirm hook ---- */
static int s_confirm_answer;    /* true to accept */
static bool ui_confirm_tx(const os_tx_intent *it)
{
	(void)it;
	return s_confirm_answer != 0;
}

/* ---- SIGN payload builder ---- */
static size_t build_sign_payload(uint8_t *o, size_t cap,
                                 const char *app_id, const uint32_t *path,
                                 size_t path_len, const uint8_t *tx,
                                 size_t tx_len)
{
	size_t n = 0;
	size_t alen = strlen(app_id);
	if (alen == 0 || alen > HD_LINK_APP_ID_MAX || path_len == 0 ||
	    path_len > HD_LINK_PATH_MAX)
		return 0;
	o[n++] = (uint8_t)alen;
	memcpy(o + n, app_id, alen); n += alen;
	o[n++] = (uint8_t)path_len;
	for (size_t i = 0; i < path_len; i++) {
		o[n++] = (uint8_t)(path[i] >> 24);
		o[n++] = (uint8_t)(path[i] >> 16);
		o[n++] = (uint8_t)(path[i] >> 8);
		o[n++] = (uint8_t)(path[i]);
	}
	if (n + tx_len > cap) return 0;
	memcpy(o + n, tx, tx_len); n += tx_len;
	return n;
}

static int reply_type(const uint8_t *buf, size_t len)
{
	uint8_t t; uint16_t seq;
	if (hd_link_parse(buf, len, &t, &seq, NULL, NULL) != 0)
		return -1;
	(void)seq;
	return t;
}

/* ---- multi-input BTC PSBT builders (native P2WPKH) ---- */
static size_t put_vi(uint8_t *o, uint64_t v)
{
	if (v < 0xfd) { o[0] = (uint8_t)v; return 1; }
	if (v < 0x10000) { o[0] = 0xfd; o[1] = v; o[2] = v >> 8; return 3; }
	o[0] = 0xfe; o[1] = v; o[2] = v >> 8; o[3] = v >> 16; o[4] = v >> 24; return 5;
}
static size_t put_u64le(uint8_t *o, uint64_t v)
{
	for (int i = 0; i < 8; i++) o[i] = (uint8_t)(v >> (8 * i));
	return 8;
}
static const uint8_t SPK[22] = { 0x00,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20 };

/* 2-in 2-out unsigned tx, both inputs native P2WPKH (empty scriptSig) */
static size_t build_btc_tx2(uint8_t *o)
{
	size_t n = 0;
	o[n++] = 1; o[n++] = 0; o[n++] = 0; o[n++] = 0;   /* version */
	n += put_vi(o + n, 2);                              /* 2 inputs */
	for (int i = 0; i < 2; i++) {
		memset(o + n, 0xaa + i, 32); n += 32;           /* prev txid */
		o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 0; /* vout */
		n += put_vi(o + n, 0);                          /* scriptSig 0 */
		o[n++] = 0xff; o[n++] = 0xff; o[n++] = 0xff; o[n++] = 0xff; /* seq */
	}
	n += put_vi(o + n, 2);                              /* 2 outputs */
	n += put_u64le(o + n, 40000);
	n += put_vi(o + n, sizeof SPK); memcpy(o + n, SPK, sizeof SPK); n += sizeof SPK;
	n += put_u64le(o + n, 60000);
	n += put_vi(o + n, sizeof SPK); memcpy(o + n, SPK, sizeof SPK); n += sizeof SPK;
	o[n++] = 0; o[n++] = 0; o[n++] = 0; o[n++] = 0;     /* locktime */
	return n;
}

/* wrap the 2-input unsigned tx with 2 witness_utxo input maps */
static size_t build_btc_psbt2(uint8_t *o, uint64_t amt0, uint64_t amt1)
{
	size_t n = 0;
	memcpy(o + n, "psbt\xff", 5); n += 5;
	/* global map: key 0x00 -> unsigned tx */
	n += put_vi(o + n, 1); o[n++] = 0x00;
	uint8_t utx[256]; size_t utxn = build_btc_tx2(utx);
	n += put_vi(o + n, utxn); memcpy(o + n, utx, utxn); n += utxn;
	o[n++] = 0x00;                                      /* global sep */
	/* two input maps, each witness_utxo (key 0x01) */
	const uint64_t amts[2] = { amt0, amt1 };
	for (int i = 0; i < 2; i++) {
		n += put_vi(o + n, 1); o[n++] = 0x01;
		n += put_vi(o + n, 8 + 1 + sizeof SPK);
		n += put_u64le(o + n, amts[i]);
		n += put_vi(o + n, sizeof SPK); memcpy(o + n, SPK, sizeof SPK); n += sizeof SPK;
		o[n++] = 0x00;                                  /* input map sep */
	}
	return n;
}

/* Check an HD_REPLY_OK carries the sig payload:
 * rc(4) | sig_count(4 BE) | [ sig64(64) | recid(1) ] × sig_count. */
static int check_sig_rep(const uint8_t *rep, size_t rn, uint8_t want_recid,
                         uint32_t want_count, const char *label)
{
	uint8_t t; uint16_t seq; const uint8_t *pl; size_t plen;
	if (rn <= 0 || hd_link_parse(rep, rn, &t, &seq, &pl, &plen) != 0) {
		printf("FAIL parse %s\n", label); return 1;
	}
	if (t != HD_REPLY_OK) { printf("FAIL type=%u %s\n", t, label); return 1; }
	pl += 4; plen -= 4;                     /* strip rc prefix */
	if (plen != 4 + (size_t)want_count * 65) { printf("FAIL sig plen=%zu %s\n", plen, label); return 1; }
	uint32_t cnt = ((uint32_t)pl[0] << 24) | ((uint32_t)pl[1] << 16) |
	               ((uint32_t)pl[2] << 8) | pl[3];
	if (cnt != want_count) { printf("FAIL count=%u want %u %s\n", cnt, want_count, label); return 1; }
	for (uint32_t i = 0; i < cnt; i++) {
		const uint8_t *e = pl + 4 + (size_t)i * 65;
		uint8_t nonzero = 0;
		for (int j = 0; j < 64; j++) nonzero |= e[j];
		if (nonzero == 0) { printf("FAIL empty sig[%u] %s\n", i, label); return 1; }
		if (e[64] != want_recid) { printf("FAIL recid[%u]=%u want %u %s\n", i, e[64], want_recid, label); return 1; }
	}
	printf("ok %s (sig plen=%zu count=%u)\n", label, plen, cnt);
	return 0;
}

int main(void)
{
	const se_driver_t *se = se_active();
	se_mock_reset();

	uint8_t rep[HD_LINK_MAX_FRAME]; int rn;

	/* provision seed + pin, unlock session (same as test_app t6) */
	uint8_t seed[64]; memset(seed, 0x11, 64);
	if (se->store_seed(seed) != SE_OK) { printf("FAIL store\n"); return 1; }
	uint8_t pin[4] = { '1', '2', '3', '4' };
	if (se->set_pin(pin, 4) != SE_OK) { printf("FAIL setpin\n"); return 1; }
	if (se->verify_pin(pin, 4, NULL, NULL) != SE_OK) { printf("FAIL unlock\n"); return 1; }

	/* build a small legacy EVM tx for "eth" */
	uint8_t tx[2048]; uint8_t to[20];
	for (int i = 0; i < 20; i++) to[i] = 0x10 + i;
	size_t tx_len = build_legacy(tx, 20, 21000, to, 1000);
	uint32_t path[3] = { 0x80000000u | 44, 0x80000000u | 60,
	                     0x80000000u | 0 };           /* m/44'/60'/0' */
	uint8_t pl[HD_LINK_MAX_PAYLOAD];
	size_t plen = build_sign_payload(pl, sizeof pl, "eth", path, 3, tx, tx_len);
	if (plen == 0) { printf("FAIL build payload\n"); return 1; }

	/* Single-verb contract: every non-SIGN verb is rejected. */
	{
		const uint8_t verbs[] = { 0x00, 0x01, 0x02, 0x04, 0x05, 0x7F, 0x80, 0xFE, 0xFF };
		for (size_t i = 0; i < sizeof verbs; i++) {
			rn = hd_link_serve(ui_confirm_tx, verbs[i], (uint16_t)(10u + i),
			                   NULL, 0, rep, sizeof rep);
			if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) {
				printf("FAIL non-SIGN verb 0x%02x not rejected\n", verbs[i]);
				return 1;
			}
		}
		printf("ok non-SIGN verbs rejected (fuzz 0x%02x..0x%02x)\n",
		       verbs[0], verbs[sizeof verbs - 1]);
	}

	/* good structured SIGN, confirm true -> OK with sig64+recid+sig_count */
	s_confirm_answer = 1;
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 4, pl, plen, rep, sizeof rep);
	if (check_sig_rep(rep, (size_t)rn, 0, 1, "sign-confirmed")) return 1;

	/* user declines -> err/auth, no signature */
	s_confirm_answer = 0;
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 5, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL declined\n"); return 1; }
	printf("ok sign-declined -> err\n");

	/* NULL confirm hook is a hard abort, never a bypass */
	s_confirm_answer = 1;
	rn = hd_link_serve(NULL, HD_CMD_SIGN, 6, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL NULL-confirm bypass\n"); return 1; }
	printf("ok NULL confirm -> err (no bypass)\n");

	/* unknown app -> state */
	s_confirm_answer = 1;
	plen = build_sign_payload(pl, sizeof pl, "nope", path, 3, tx, tx_len);
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 7, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL unknown app\n"); return 1; }
	printf("ok unknown app -> err\n");

	/* wrong coin branch path (m/44'/0'/0' for btc) -> param */
	uint32_t bad_path[3] = { 0x80000000u | 44, 0x80000000u | 0,
	                         0x80000000u | 0 };
	plen = build_sign_payload(pl, sizeof pl, "eth", bad_path, 3, tx, tx_len);
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 8, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL wrong path\n"); return 1; }
	printf("ok wrong coin path -> err\n");

	/* malformed tx -> param */
	plen = build_sign_payload(pl, sizeof pl, "eth", path, 3, tx, 8);
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 9, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL short tx\n"); return 1; }
	printf("ok malformed tx -> err\n");

	/* truncated/bad payload shapes -> param */
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 10, pl, 1, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL len1\n"); return 1; }
	uint8_t tiny[2] = { 0x10, 0x05 };               /* app_len 16, no room */
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 11, tiny, sizeof tiny, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL truncated\n"); return 1; }
	printf("ok bad payload shapes -> err\n");

	/* full wire roundtrip: host encodes the frame, device serves it */
	{
		uint8_t frm[HD_LINK_MAX_FRAME];
		plen = build_sign_payload(pl, sizeof pl, "eth", path, 3, tx, tx_len);
		int fn = hd_link_frame_cmd(HD_CMD_SIGN, 21, pl, plen, frm, sizeof frm);
		if (fn <= 0) { printf("FAIL frame enc\n"); return 1; }
		uint8_t type; uint16_t seq; const uint8_t *p; size_t pn;
		if (hd_link_parse(frm, (size_t)fn, &type, &seq, &p, &pn) != 0 ||
		    type != HD_CMD_SIGN || seq != 21) {
			printf("FAIL frame parse\n"); return 1;
		}
		s_confirm_answer = 1;
		rn = hd_link_serve(ui_confirm_tx, type, seq, p, pn, rep, sizeof rep);
		if (check_sig_rep(rep, (size_t)rn, 0, 1, "wire-roundtrip")) return 1;
		printf("ok frame wire roundtrip\n");
	}

	/* multi-input BTC PSBT -> reply carries one sig per input (sig_count=2) */
	{
		uint8_t psbt[1024];
		size_t pn = build_btc_psbt2(psbt, 60000, 50000);   /* in 110000, out 100000, fee 10000 */
		uint32_t bpath[3] = { 0x80000000u | 84, 0x80000000u | 0, 0x80000000u | 0 };
		size_t bplen = build_sign_payload(pl, sizeof pl, "btc", bpath, 3, psbt, pn);
		if (bplen == 0) { printf("FAIL btc payload\n"); return 1; }
		s_confirm_answer = 1;
		rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 22, pl, bplen, rep, sizeof rep);
		if (check_sig_rep(rep, (size_t)rn, 0, 2, "btc-2in-sign")) return 1;
		printf("ok multi-input BTC -> per-input signatures\n");
	}

	/* wiped device refuses to sign -> state */
	se_mock_reset();
	plen = build_sign_payload(pl, sizeof pl, "eth", path, 3, tx, tx_len);
	rn = hd_link_serve(ui_confirm_tx, HD_CMD_SIGN, 30, pl, plen, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL unprovisioned\n"); return 1; }
	printf("ok unprovisioned -> err\n");

	printf("ALL PASS\n");
	return 0;
}
