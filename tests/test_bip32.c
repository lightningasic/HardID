/* secp256k1 pubkey + BIP32 tests — official vectors. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/bip32.h"
#include "../core/secp256k1.h"

#include "../core/sha512.c"
#include "../core/hkdf.c"
#include "../core/base58.c"
#include "../core/secp256k1.c"
#include "../core/bip32.c"

static void hex(const uint8_t *d, size_t n, char *o)
{
	static const char *h = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { o[i*2]=h[d[i]>>4]; o[i*2+1]=h[d[i]&0xf]; }
	o[n*2]=0;
}
static size_t unhex(const char *s, uint8_t *out)
{
	size_t n = 0;
	while (s[0] && s[1]) { unsigned v; sscanf(s, "%2x", &v); out[n++]=(uint8_t)v; s+=2; }
	return n;
}

int main(void)
{
	uint8_t pub[33]; char hx[200];

	/* 1 secp256k1 G*1 = generator (compressed 0279be667e...) */
	uint8_t one[32] = {0}; one[31] = 1;
	if (os_secp256k1_pubkey(one, pub) != 0) { printf("FAIL t1\n"); return 1; }
	hex(pub, 33, hx);
	const char *G = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
	if (strcmp(hx, G) != 0) { printf("FAIL t1\n got %s\nwant %s\n", hx, G); return 1; }
	printf("PASS t1 pubkey of 1 = generator\n");

	/* 2 pubkey of 2 — known compressed */
	uint8_t two[32] = {0}; two[31] = 2;
	os_secp256k1_pubkey(two, pub);
	hex(pub, 33, hx);
	const char *G2 = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
	if (strcmp(hx, G2) != 0) { printf("FAIL t2\n got %s\nwant %s\n", hx, G2); return 1; }
	printf("PASS t2 pubkey of 2\n");

	/* 3 BIP32 test vector 1 — seed 000102030405060708090a0b0c0d0e0f
	 * master xprv/xpub from BIP32 spec */
	uint8_t seed[16];
	unhex("000102030405060708090a0b0c0d0e0f", seed);
	os_hdnode m;
	if (os_bip32_from_seed(seed, 16, &m) != 0) { printf("FAIL t3 seed\n"); return 1; }

	char xprv[OS_BIP32_XKEY_MAX], xpub[OS_BIP32_XKEY_MAX];
	/* mainnet versions: xprv 0x0488ADE4, xpub 0x0488B21E */
	os_bip32_serialize(&m, true,  0x0488ADE4, xprv, sizeof xprv);
	os_bip32_serialize(&m, false, 0x0488B21E, xpub, sizeof xpub);
	const char *wxprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPP"
		"qjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
	const char *wxpub = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhe"
		"PY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
	if (strcmp(xprv, wxprv) != 0) { printf("FAIL t3 xprv\n got %s\nwant %s\n", xprv, wxprv); return 1; }
	if (strcmp(xpub, wxpub) != 0) { printf("FAIL t3 xpub\n got %s\nwant %s\n", xpub, wxpub); return 1; }
	printf("PASS t3 BIP32 master xprv+xpub\n");

	/* 4 BIP32 vector 1 chain m/0' — known xprv */
	os_hdnode n = m;
	if (os_bip32_derive_path(&n, "m/0'") != 0) { printf("FAIL t4 derive\n"); return 1; }
	char xprv0[OS_BIP32_XKEY_MAX];
	os_bip32_serialize(&n, true, 0x0488ADE4, xprv0, sizeof xprv0);
	const char *wxprv0 = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvU"
		"xt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
	if (strcmp(xprv0, wxprv0) != 0) { printf("FAIL t4\n got %s\nwant %s\n", xprv0, wxprv0); return 1; }
	printf("PASS t4 BIP32 m/0' derivation\n");

	/* 5 deeper path m/0'/1 — vector */
	n = m;
	if (os_bip32_derive_path(&n, "m/0'/1") != 0) { printf("FAIL t5\n"); return 1; }
	char xpub01[OS_BIP32_XKEY_MAX];
	os_bip32_serialize(&n, false, 0x0488B21E, xpub01, sizeof xpub01);
	const char *wxpub01 = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
	if (strcmp(xpub01, wxpub01) != 0) { printf("FAIL t5\n got %s\nwant %s\n", xpub01, wxpub01); return 1; }
	printf("PASS t5 BIP32 m/0'/1 derivation\n");

	printf("\nALL BIP32 TESTS PASSED\n");
	return 0;
}
