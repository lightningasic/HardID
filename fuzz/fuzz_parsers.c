/*
 * OpenShield — fuzz harness (GCC ASan/UBSan, no libFuzzer dependency)
 *
 * Drives the parsers with generated inputs: seeds from valid structures
 * with systematic bit/byte mutations, plus random bytes. Any crash, ASan
 * report, or UBSan report is a bug. Parsers must never crash on any input.
 *
 * Build:  gcc -fsanitize=address,undefined -g -O1 -o fuzz_parsers \
 *         fuzz_parsers.c ../core/psbt.c ../core/clearsign.c ../core/keccak.c \
 *         ../core/eip712.c
 * Run:    ./fuzz_parsers [iterations]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../core/psbt.h"
#include "../core/clearsign.h"
#include "../core/eip712.h"
#include "../core/keccak.h"

/* deterministic PRNG so failures reproduce */
static uint64_t rng_state;
static uint32_t frand(void)
{
	rng_state = rng_state * 6364136223846793005ULL + 1442695040888963407ULL;
	return (uint32_t)(rng_state >> 33);
}
static uint8_t fbyte(void) { return (uint8_t)frand(); }

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
	if (l && d) memcpy(o+h,d,l);   /* guard: never memcpy NULL */
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

/* ---- targets ---- */

static void fuzz_psbt(const uint8_t *d, size_t n)
{
	os_psbt_summary s;
	os_psbt_parse(d, n, NULL, &s);
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
	if (n > 15) { size_t vl = (n-63) < 15 ? (n-63) : 15; if (n>63) memcpy(dom.version, d+63, vl); }
	dom.chain_id = n >= 8 ? ((const uint64_t*)d)[0] : 1;
	if (n >= 20) memcpy(dom.verifying_contract, d, 20);
	uint8_t out[32];
	os_eip712_domain_separator(&dom, out);
}

/* ---- mutation ---- */

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

int main(int argc, char **argv)
{
	long iters = argc > 1 ? atol(argv[1]) : 200000;
	uint8_t seed_psbt[1024], seed_evm[256];
	size_t n_psbt = build_psbt(seed_psbt, sizeof seed_psbt);
	size_t n_evm = build_evm(seed_evm, sizeof seed_evm);
	uint8_t work[1024];

	rng_state = 0x853c49e6748fea9bULL;

	for (long i = 0; i < iters; i++) {
		int target = frand() % 4;
		int mode = frand() % 10;
		size_t n;

		if (mode < 2) {
			/* pure random bytes */
			n = frand() % 300;
			for (size_t k = 0; k < n; k++) work[k] = fbyte();
		} else if (target == 0 || target == 1) {
			/* mutate valid structure */
			if (target == 0) {
				n = n_psbt < sizeof work ? n_psbt : sizeof work;
				memcpy(work, seed_psbt, n);
			} else {
				n = n_evm < sizeof work ? n_evm : sizeof work;
				memcpy(work, seed_evm, n);
			}
			mutate(work, n, mode > 5);
			/* occasionally truncate */
			if (frand() % 7 == 0 && n > 1)
				n = 1 + frand() % n;
		} else {
			/* structured-ish random */
			n = frand() % 200;
			for (size_t k = 0; k < n; k++) work[k] = fbyte();
			if (n >= 5 && frand() % 2) memcpy(work, "psbt\xff", 5);
		}

		switch (target) {
		case 0: fuzz_psbt(work, n); break;
		case 1: fuzz_evm(work, n); break;
		case 2: fuzz_keccak(work, n); break;
		case 3: fuzz_domain(work, n); break;
		}
	}

	printf("fuzz: %ld iterations, no crash (ASan/UBSan clean)\n", iters);
	return 0;
}
