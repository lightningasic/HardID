/*
 * HardID — full-surface fuzz harness (GCC ASan/UBSan, no libFuzzer dep)
 *
 * Drives EVERY untrusted-input parser in core/ with mutated seeds and random
 * bytes. Any crash / ASan / UBSan report is a bug. Parsers must never crash
 * or go out of bounds on any input.
 *
 * Targets (untrusted inputs from host/USB):
 *   PSBT, EVM tx (RLP/ERC20), CBOR, EIP-712 domain, BIP39 mnemonic,
 *   BIP32 path, linkproto frame, CTAP2 request, CTAPHID 64-byte packets,
 *   tx assembly (sig->DER/witness), secp256r1/256k1 pubkey parse, keccak.
 *
 * Build (see fuzz/Makefile full target):
 *   gcc -fsanitize=address,undefined -g -O1 -o fuzz_full fuzz_full.c \
 *       <all core .c listed in Makefile>
 * Run: ./fuzz_full [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../core/psbt.h"
#include "../core/clearsign.h"
#include "../core/eip712.h"
#include "../core/keccak.h"
#include "../core/cbor.h"
#include "../core/bip39.h"
#include "../core/bip32.h"
#include "../core/base58.h"
#include "../core/linkproto.h"
#include "../core/ctap2.h"
#include "../core/fido_ctaphid.h"
#include "../core/tx_asm.h"
#include "../core/secp256r1.h"
#include "../core/secp256k1.h"

/* deterministic PRNG so failures reproduce */
static uint64_t rng_state;
static uint32_t frand(void)
{
	rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (uint32_t)(rng_state >> 33);
}
static uint8_t fbyte(void) { return (uint8_t)frand(); }

#define WORK_MAX 1024
static uint8_t work[WORK_MAX];

/* Copy up to n bytes, NUL-terminate for string-consuming targets. */
static size_t to_cstr(const uint8_t *d, size_t n)
{
	size_t m = n < (WORK_MAX - 1) ? n : (WORK_MAX - 1);
	memcpy(work, d, m);
	work[m] = '\0';
	return m;
}

/* ---- seed corpus builders (valid structures) ---- */

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
static const uint8_t SPK[22] = {0x00,0x14, 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

static size_t build_psbt(uint8_t *o, size_t cap)
{
	uint8_t tx[256]; size_t txn = 0;
	tx[txn++]=1;tx[txn++]=0;tx[txn++]=0;tx[txn++]=0;
	txn += put_varint(tx+txn,1);
	memset(tx+txn,0xaa,32); txn+=32;
	tx[txn++]=0;tx[txn++]=0;tx[txn++]=0;tx[txn++]=0;
	txn += put_varint(tx+txn,0);
	tx[txn++]=0xff;tx[txn++]=0xff;tx[txn++]=0xff;tx[txn++]=0xff;
	txn += put_varint(tx+txn,1);
	txn += put_u64le(tx+txn,40000);
	txn += put_varint(tx+txn,sizeof SPK);
	memcpy(tx+txn,SPK,sizeof SPK); txn+=sizeof SPK;
	tx[txn++]=0;tx[txn++]=0;tx[txn++]=0;tx[txn++]=0;

	size_t n = 0;
	memcpy(o+n,"psbt\xff",5); n+=5;
	n += put_varint(o+n,1); o[n++]=0x00;
	n += put_varint(o+n,txn);
	if (n + txn >= cap) return 0;
	memcpy(o+n,tx,txn); n+=txn;
	o[n++]=0x00;
	n += put_varint(o+n,1); o[n++]=0x01;
	n += put_varint(o+n, 8+sizeof SPK);
	if (n + 8 + sizeof SPK >= cap) return 0;
	n += put_u64le(o+n,100000);
	memcpy(o+n,SPK,sizeof SPK); n+=sizeof SPK;
	o[n++]=0x00;
	return n;
}

static size_t rlp_hdr(uint8_t *o, int list, size_t l)
{
	uint8_t base = list ? 0xc0 : 0x80;
	if (l < 56) { o[0]=base+l; return 1; }
	o[0]=base+56; o[1]=(uint8_t)l; return 2;
}
static size_t rlp_str(uint8_t *o, const uint8_t *d, size_t l)
{
	size_t h = rlp_hdr(o,0,l);
	if (l && d) memcpy(o+h,d,l);
	return h+l;
}
static size_t rlp_u(uint8_t *o, uint64_t v)
{
	uint8_t b[8]; int n=0;
	if (v==0){o[0]=0x80;return 1;}
	while(v){b[7-n++]=v&0xff;v>>=8;}
	return rlp_str(o,b+8-n,n);
}
static size_t build_evm(uint8_t *o, size_t cap)
{
	uint8_t tmp[256]; size_t t=0;
	uint8_t to[20]; memset(to,0x11,20);
	t += rlp_u(tmp+t,1);
	t += rlp_u(tmp+t,20);
	t += rlp_u(tmp+t,21000);
	t += rlp_str(tmp+t,to,20);
	t += rlp_u(tmp+t,1000);
	t += rlp_str(tmp+t,NULL,0);
	if (t + 3 >= cap) return 0;
	size_t h = rlp_hdr(o,1,t);
	memcpy(o+h,tmp,t);
	return h+t;
}

static size_t build_cbor(uint8_t *o, size_t cap)
{
	cbor_writer_t w;
	cbor_writer_init(&w, o, cap);
	if (cbor_write_map_head(&w, 2) ||
	    cbor_write_uint(&w, 1) ||
	    cbor_write_bytes(&w, "\xaa\xbb\xcc\xdd", 4) ||
	    cbor_write_uint(&w, 2) ||
	    cbor_write_array_head(&w, 3) ||
	    cbor_write_uint(&w, 0) || cbor_write_int(&w, -7) ||
	    cbor_write_bool(&w, true) ||
	    cbor_write_text(&w, "public-key"))
		return 0;
	return w.len;
}

/* A valid-ish CTAP2 getAssertion request: cmd byte + map. */
static size_t build_ctap2(uint8_t *o, size_t cap)
{
	size_t n = 0;
	o[n++] = 0x02;   /* CTAP2_CMD_GET_ASSERTION */
	cbor_writer_t w;
	cbor_writer_init(&w, o + 1, cap - 1);
	cbor_write_map_head(&w, 2);
	cbor_write_uint(&w, 1);   /* rpId */
	cbor_write_text(&w, "example.com");
	cbor_write_uint(&w, 2);   /* clientDataHash */
	cbor_write_bytes(&w, "\x00\x01\x02\x03\x04\x05\x06\x07"
	                      "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
	                      "\x10\x11\x12\x13\x14\x15\x16\x17"
	                      "\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f", 32);
	return 1 + w.len;
}

/* ---- targets ---- */

static void fuzz_psbt(const uint8_t *d, size_t n)
{
	os_psbt_summary s;
	os_psbt_parse(d, n, NULL, 0, &s);
}
static void fuzz_evm(const uint8_t *d, size_t n)
{
	os_tx_intent it;
	os_clearsign_parse_evm(d, n, &it);
}
static void fuzz_keccak(const uint8_t *d, size_t n)
{
	uint8_t out[32];
	os_keccak256(d, n, out);
}
static void fuzz_domain(const uint8_t *d, size_t n)
{
	os_eip712_domain dom;
	memset(&dom, 0, sizeof dom);
	size_t nl = n < 63 ? n : 63;
	memcpy(dom.name, d, nl);
	dom.name[nl] = 0;
	if (n > 63) {
		size_t vl = (n - 63) < 15 ? (n - 63) : 15;
		memcpy(dom.version, d + 63, vl);
		dom.version[vl] = 0;
	}
	if (n >= 8) memcpy(&dom.chain_id, d, 8);
	else dom.chain_id = 1;
	if (n >= 20) memcpy(dom.verifying_contract, d, 20);
	uint8_t out[32];
	os_eip712_domain_separator(&dom, out);
}
static void fuzz_cbor(const uint8_t *d, size_t n)
{
	cbor_reader_t rd;
	cbor_reader_init(&rd, d, n, 4096);
	while (cbor_peek_type(&rd, &(uint8_t){0}, &(uint8_t){0}) == CBOR_OK)
		if (cbor_skip(&rd) != CBOR_OK)
			break;
}
static void fuzz_bip39(const uint8_t *d, size_t n)
{
	size_t m = to_cstr(d, n);
	uint8_t ent[32];
	uint8_t seed64[64];
	os_bip39_mnemonic_to_entropy((const char *)work, ent, sizeof ent);
	/* PBKDF2 (2048 rounds) is expensive — run it only 1 in 64 inputs */
	if ((d[0] & 0x3f) == 0)
		os_bip39_mnemonic_to_seed((const char *)work, NULL, seed64);
	/* prefix resolution over the (possibly junk) first bytes */
	char pfx[16];
	size_t pl = m < 15 ? m : 15;
	memcpy(pfx, work, pl);
	pfx[pl] = 0;
	os_bip39_words_with_prefix(pfx, pl, NULL, 0);
}
static void fuzz_bip32(const uint8_t *d, size_t n)
{
	to_cstr(d, n);
	os_hdnode node;
	uint8_t seed[64];
	for (int i = 0; i < 64; i++) seed[i] = fbyte();
	os_bip32_from_seed(seed, sizeof seed, &node);
	os_bip32_derive_path(&node, (const char *)work);
}
static void fuzz_linkproto(const uint8_t *d, size_t n)
{
	uint8_t type; uint16_t seq; const uint8_t *pl; size_t plen;
	/* feed progressively: byte-by-byte re-parse, plus whole-buffer */
	for (size_t i = 1; i <= n; i++)
		hd_link_parse(d, i, &type, &seq, &pl, &plen);
	if (n > 0)
		hd_link_parse(d, n, &type, &seq, &pl, &plen);
}
static void fuzz_ctap2(const uint8_t *d, size_t n)
{
	uint8_t resp[CTAPHID_MAX_MSG];
	size_t rlen = 0;
	ctap2_handle(d, n, resp, sizeof resp, &rlen);
}
static void fuzz_ctaphid(const uint8_t *d, size_t n)
{
	ctaphid_t h;
	ctaphid_init(&h);
	uint8_t out[16][64];
	/* feed 64-byte packets derived from the buffer */
	size_t off = 0;
	while (off + 64 <= n) {
		ctaphid_feed(&h, d + off, out, 16);
		off += 64;
	}
	(void)n;
}
static void fuzz_txasm(const uint8_t *d, size_t n)
{
	uint8_t sig64[64];
	if (n >= 64) memcpy(sig64, d, 64);
	else { memcpy(sig64, d, n); memset(sig64 + n, 0, 64 - n); }
	uint8_t recid = n > 0 ? (d[0] & 1) : 0;
	uint8_t chain = n > 1 ? d[1] : 1;
	uint8_t out[128]; size_t ol;
	os_evm_sig_assemble(chain, sig64, recid, out, sizeof out, &ol);
	os_btc_sig_to_der(sig64, OS_BTC_SIGHASH_ALL, out, sizeof out, &ol);
	uint8_t pub33[33];
	memset(pub33, 0x02, sizeof pub33);
	os_btc_witness_p2wpkh(sig64, OS_BTC_SIGHASH_ALL, pub33, out, sizeof out, &ol);
}
static void fuzz_secp(const uint8_t *d, size_t n)
{
	/* point_out is a 96-byte jacobian point (3 x 4-limb fe). Provide a
	 * real buffer — the parse APIs write into it (non-NULL contract). */
	uint64_t ptbuf[12];
	/* r256 pubkey parse over arbitrary bytes */
	uint8_t pub65[65];
	os_secp256r1_parse_pubkey(d, n, ptbuf);
	os_secp256r1_pubkey(d, pub65);
	/* k1 pubkey parse */
	os_secp256k1_parse_pubkey(d, ptbuf);
	uint8_t pub33[33];
	os_secp256k1_pubkey(d, pub33);
}
static void fuzz_base58(const uint8_t *d, size_t n)
{
	/* encode path: payload is device-internal, but still fuzz for UB */
	uint8_t payload[21];
	if (n >= 21) memcpy(payload, d, 21);
	else { memcpy(payload, d, n); memset(payload + n, 0, 21 - n); }
	char out[40];
	os_base58check_encode(payload[0], payload + 1, out, sizeof out);
	os_base58_encode_check(payload, sizeof payload, out, sizeof out);
	os_sha256d(d, n, out);
}

static void mutate(uint8_t *d, size_t n, int aggressive)
{
	int flips = aggressive ? (1 + frand() % 8) : 1;
	for (int i = 0; i < flips && n > 0; i++) {
		size_t pos = frand() % n;
		switch (frand() % 4) {
		case 0: d[pos] ^= 1 << (frand() % 8); break;
		case 1: d[pos] = fbyte(); break;
		case 2: d[pos] ^= 0xff; break;
		case 3: if (pos+1<n) { uint8_t t=d[pos];d[pos]=d[pos+1];d[pos+1]=t; } break;
		}
	}
}

#define N_TARGETS 13
typedef void (*fuzz_fn)(const uint8_t *, size_t);
static const fuzz_fn targets[N_TARGETS] = {
	fuzz_psbt, fuzz_evm, fuzz_keccak, fuzz_domain, fuzz_cbor,
	fuzz_bip39, fuzz_bip32, fuzz_linkproto, fuzz_ctap2, fuzz_ctaphid,
	fuzz_txasm, fuzz_secp, fuzz_base58,
};

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200000;
	uint8_t seed_psbt[1024], seed_evm[256], seed_cbor[256], seed_ctap2[512];
	size_t n_psbt = build_psbt(seed_psbt, sizeof seed_psbt);
	size_t n_evm = build_evm(seed_evm, sizeof seed_evm);
	size_t n_cbor = build_cbor(seed_cbor, sizeof seed_cbor);
	size_t n_ctap2 = build_ctap2(seed_ctap2, sizeof seed_ctap2);

	rng_state = argc > 2 ? strtoull(argv[2], NULL, 0)
	                     : 0x853c49e6748fea9bULL;

	for (long i = 0; i < iters; i++) {
		int target = frand() % N_TARGETS;
		int mode = frand() % 10;
		size_t n;

		if (mode < 2) {
			n = frand() % 320;
			for (size_t k = 0; k < n; k++) work[k] = fbyte();
		} else if (mode < 6) {
			/* mutate a valid structure for structure-bearing targets */
			switch (target) {
			case 0:  n = n_psbt < WORK_MAX ? n_psbt : WORK_MAX; memcpy(work, seed_psbt, n); break;
			case 1:  n = n_evm < WORK_MAX ? n_evm : WORK_MAX; memcpy(work, seed_evm, n); break;
			case 4:  n = n_cbor < WORK_MAX ? n_cbor : WORK_MAX; memcpy(work, seed_cbor, n); break;
			case 8:  n = n_ctap2 < WORK_MAX ? n_ctap2 : WORK_MAX; memcpy(work, seed_ctap2, n); break;
			default: n = frand() % 200; for (size_t k=0;k<n;k++) work[k]=fbyte(); break;
			}
			mutate(work, n, mode > 4);
			if (frand() % 7 == 0 && n > 1)
				n = 1 + frand() % n;
		} else {
			n = frand() % 200;
			for (size_t k = 0; k < n; k++) work[k] = fbyte();
			if (n >= 5 && frand() % 3 == 0) work[0] = 0xa3;
			/* bias string targets toward text-ish bytes */
			if ((target == 5 || target == 6) && n > 0 && frand() % 2 == 0)
				for (size_t k = 0; k < n; k++) work[k] = 'a' + frand() % 26;
		}

		targets[target](work, n);
	}

	printf("fuzz-full: %ld iterations, no crash (ASan/UBSan clean)\n", iters);
	return 0;
}
