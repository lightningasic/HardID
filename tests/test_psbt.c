/* PSBT parser tests: build a synthetic PSBT, verify summary. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/psbt.h"

#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/psbt.c"

/* ---- builders ---- */
static size_t put_varint(uint8_t *o, uint64_t v)
{
	if (v < 0xfd) { o[0] = v; return 1; }
	if (v < 0x10000) { o[0]=0xfd; o[1]=v; o[2]=v>>8; return 3; }
	o[0]=0xfe; o[1]=v; o[2]=v>>8; o[3]=v>>16; o[4]=v>>24; return 5;
}
static size_t put_u64le(uint8_t *o, uint64_t v)
{
	for (int i = 0; i < 8; i++) o[i] = (v >> (8*i)) & 0xff;
	return 8;
}

/* P2WPKH script: 0014 <20> */
static const uint8_t SPK[22] = {0x00,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

/* build a 1-in 2-out unsigned tx (legacy serialization) */
static size_t build_tx(uint8_t *o, uint64_t amt0, uint64_t amt1)
{
	size_t n = 0;
	/* version */
	o[n++]=1; o[n++]=0; o[n++]=0; o[n++]=0;
	/* 1 input */
	n += put_varint(o+n, 1);
	memset(o+n, 0xaa, 32); n += 32;      /* prev txid */
	o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;  /* vout */
	n += put_varint(o+n, 0);              /* scriptSig len 0 */
	o[n++]=0xff;o[n++]=0xff;o[n++]=0xff;o[n++]=0xff; /* seq */
	/* 2 outputs */
	n += put_varint(o+n, 2);
	n += put_u64le(o+n, amt0);
	n += put_varint(o+n, sizeof SPK);
	memcpy(o+n, SPK, sizeof SPK); n += sizeof SPK;
	n += put_u64le(o+n, amt1);
	n += put_varint(o+n, sizeof SPK);
	memcpy(o+n, SPK, sizeof SPK); n += sizeof SPK;
	/* locktime */
	o[n++]=0;o[n++]=0;o[n++]=0;o[n++]=0;
	return n;
}

/* build a full PSBT with given witness_utxo amount + the unsigned tx */
static size_t build_psbt(uint8_t *o, uint64_t in_amt, const uint8_t *tx, size_t txn)
{
	size_t n = 0;
	memcpy(o+n, "psbt\xff", 5); n += 5;
	/* global map: key 0x00 -> unsigned tx */
	n += put_varint(o+n, 1); o[n++] = 0x00;
	n += put_varint(o+n, txn);
	memcpy(o+n, tx, txn); n += txn;
	o[n++] = 0x00; /* global map separator */
	/* input map 0: key 0x01 (witness_utxo) -> amount+script */
	n += put_varint(o+n, 1); o[n++] = 0x01;
	n += put_varint(o+n, 8 + 1 + sizeof SPK);   /* CTxOut: amt + varint(len) + script */
	n += put_u64le(o+n, in_amt);
	n += put_varint(o+n, sizeof SPK);
	memcpy(o+n, SPK, sizeof SPK); n += sizeof SPK;
	o[n++] = 0x00; /* input map separator */
	/* output maps: none */
	return n;
}

/* change check state: mark the Nth output as change */
static int g_call;
static int g_change_at;
static bool chk_nth(const uint8_t *sc, size_t sl)
{
	(void)sc; (void)sl;
	g_call++;
	return g_call == g_change_at;
}

int main(void)
{
	uint8_t tx[512], psbt[1024];
	os_psbt_summary s;

	/* 1 basic: in=100000, out0=40000(spend), out1=55000(change via check) */
	size_t txn = build_tx(tx, 40000, 55000);
	size_t pn = build_psbt(psbt, 100000, tx, txn);
	g_call = 0; g_change_at = 2; /* second output is change */
	if (os_psbt_parse(psbt, pn, chk_nth, 0, &s) != 0) { printf("FAIL t1 parse\n"); return 1; }
	if (s.fee != 5000) { printf("FAIL t1 fee=%llu\n", (unsigned long long)s.fee); return 1; }
	if (s.spend_count != 1) { printf("FAIL t1 spend=%u\n", s.spend_count); return 1; }
	if (s.output_count != 2) { printf("FAIL t1 nout=%u\n", s.output_count); return 1; }
	printf("PASS t1 fee + change detection (fee=%llu spend=%u)\n",
		(unsigned long long)s.fee, s.spend_count);

	/* 2 bech32 address produced for P2WPKH */
	if (strncmp(s.outputs[0].address, "bc1q", 4) != 0) { printf("FAIL t2 addr=%s\n", s.outputs[0].address); return 1; }
	printf("PASS t2 bech32 address: %s\n", s.outputs[0].address);

	/* 3 fee = in - out sanity: underflow rejected */
	txn = build_tx(tx, 60000, 55000);
	pn = build_psbt(psbt, 100000, tx, txn); /* in 100000 < out 115000 */
	if (os_psbt_parse(psbt, pn, NULL, 0, &s) == 0) { printf("FAIL t3 underflow accepted\n"); return 1; }
	printf("PASS t3 underflow (out>in) rejected\n");

	/* 4 bad magic rejected */
	psbt[0] = 'X';
	if (os_psbt_parse(psbt, pn, NULL, 0, &s) == 0) { printf("FAIL t4\n"); return 1; }
	printf("PASS t4 bad magic rejected\n");

	/* 5 no unsigned tx -> rejected */
	{
		uint8_t bad[16];
		size_t bn = 0;
		memcpy(bad, "psbt\xff", 5); bn = 5;
		bad[bn++] = 0x00; /* empty global map */
		if (os_psbt_parse(bad, bn, NULL, 0, &s) == 0) { printf("FAIL t5\n"); return 1; }
		printf("PASS t5 missing unsigned tx rejected\n");
	}

	/* 6 per-coin address encoding (M-1): the SAME P2WPKH output script must
	 * render with each chain's own HRP / base58 version. LTC -> ltc1q…,
	 * DOGE has no segwit -> hex fallback (addr_valid=false), BTC default
	 * unchanged. */
	{
		txn = build_tx(tx, 40000, 55000);
		pn = build_psbt(psbt, 100000, tx, txn);
		if (os_psbt_parse(psbt, pn, NULL, 2, &s) != 0) { printf("FAIL t6 ltc parse\n"); return 1; }
		if (strncmp(s.outputs[0].address, "ltc1q", 5) != 0) {
			printf("FAIL t6 ltc addr=%s\n", s.outputs[0].address); return 1;
		}
		if (os_psbt_parse(psbt, pn, NULL, 3, &s) != 0) { printf("FAIL t6 doge parse\n"); return 1; }
		if (s.outputs[0].addr_valid) {
			printf("FAIL t6 doge must not render segwit addr (%s)\n",
			       s.outputs[0].address); return 1;
		}
		if (os_psbt_parse(psbt, pn, NULL, 0, &s) != 0) { printf("FAIL t6 btc parse\n"); return 1; }
		if (strncmp(s.outputs[0].address, "bc1q", 4) != 0) {
			printf("FAIL t6 btc addr=%s\n", s.outputs[0].address); return 1;
		}
		printf("PASS t6 per-coin address encoding (ltc1q / doge-hex / bc1q)\n");
	}

	/* 7 BIP143 official vector (M-2): the native-P2WPKH example from
	 * BIP143. Unsigned tx has 2 inputs (P2PK + P2WPKH); we sighash input
	 * index 1 with witness_spk 00141d0f… and amount 6 BTC, SIGHASH_ALL.
	 * Spec sigHash = c37af311…8cb670. */
	{
		static const uint8_t utx[] = {
			0x01,0x00,0x00,0x00,0x02,
			0xff,0xf7,0xf7,0x88,0x1a,0x80,0x99,0xaf,0xa6,0x94,0x0d,0x42,0xd1,0xe7,0xf6,0x36,
			0x2b,0xec,0x38,0x17,0x1e,0xa3,0xed,0xf4,0x33,0x54,0x1d,0xb4,0xe4,0xad,0x96,0x9f,
			0x00,0x00,0x00,0x00,0x00,0xee,0xff,0xff,0xff,
			0xef,0x51,0xe1,0xb8,0x04,0xcc,0x89,0xd1,0x82,0xd2,0x79,0x65,0x5c,0x3a,0xa8,0x9e,
			0x81,0x5b,0x1b,0x30,0x9f,0xe2,0x87,0xd9,0xb2,0xb5,0x5d,0x57,0xb9,0x0e,0xc6,0x8a,
			0x01,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,
			0x02,
			0x20,0x2c,0xb2,0x06,0x00,0x00,0x00,0x00,
			0x19,0x76,0xa9,0x14,0x82,0x80,0xb3,0x7d,0xf3,0x78,0xdb,0x99,0xf6,0x6f,0x85,0xc9,
			0x5a,0x78,0x3a,0x76,0xac,0x7a,0x6d,0x59,0x88,0xac,
			0x90,0x93,0x51,0x0d,0x00,0x00,0x00,0x00,
			0x19,0x76,0xa9,0x14,0x3b,0xde,0x42,0xdb,0xee,0x7e,0x4d,0xbe,0x6a,0x21,0xb2,0xd5,
			0x0c,0xe2,0xf0,0x16,0x7f,0xaa,0x81,0x59,0x88,0xac,
			0x11,0x00,0x00,0x00,
		};
		static const uint8_t spk[22] = {
			0x00,0x14,0x1d,0x0f,0x17,0x2a,0x0e,0xcb,0x48,0xae,0xe1,0xbe,0x1f,
			0x26,0x87,0xd2,0x96,0x3a,0xe3,0x3f,0x71,0xa1,
		};
		static const uint8_t want[32] = {
			0xc3,0x7a,0xf3,0x11,0x16,0xd1,0xb2,0x7c,0xaf,0x68,0xaa,0xe9,0xe3,0xac,
			0x82,0xf1,0x47,0x79,0x29,0x01,0x4d,0x5b,0x91,0x76,0x57,0xd0,0xeb,0x49,
			0x47,0x8c,0xb6,0x70,
		};
		uint8_t dg[32];
		if (os_btc_bip143_sighash_tx(utx, sizeof utx, 1, spk, sizeof spk,
		                             600000000ULL, 1, dg) != 0) {
			printf("FAIL t7 sighash rc\n"); return 1;
		}
		if (memcmp(dg, want, 32) != 0) {
			printf("FAIL t7 BIP143 sighash mismatch\n"); return 1;
		}
		/* sighash_type != ALL refused; non-P2WPKH spk refused; bad index */
		if (os_btc_bip143_sighash_tx(utx, sizeof utx, 1, spk, sizeof spk,
		                             600000000ULL, 3, dg) == 0) {
			printf("FAIL t7 SINGLE accepted\n"); return 1;
		}
		if (os_btc_bip143_sighash_tx(utx, sizeof utx, 1, spk, 21,
		                             600000000ULL, 1, dg) == 0) {
			printf("FAIL t7 bad spk accepted\n"); return 1;
		}
		if (os_btc_bip143_sighash_tx(utx, sizeof utx, 5, spk, sizeof spk,
		                             600000000ULL, 1, dg) == 0) {
			printf("FAIL t7 bad index accepted\n"); return 1;
		}
		printf("PASS t7 BIP143 official sighash vector + refusals\n");
	}

	printf("\nALL PSBT TESTS PASSED\n");
	return 0;
}
