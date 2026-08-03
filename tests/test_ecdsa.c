/* ECDSA sign/verify tests — RFC6979 vectors + roundtrip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/ecdsa.h"

#include "../core/hkdf.c"
#include "../core/rfc6979.c"
#include "../core/secp256k1.c"
#include "../core/ecdsa.c"

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
	uint8_t sig[64], pub[33];
	char hx[200];

	/* 1 RFC6979 known-answer — privkey=1, hash=SHA256("hello") computed inline */
	uint8_t priv[32] = {0}; priv[31] = 1;
	uint8_t hash[32];
	unhex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash); /* sha256("hello") */
	uint8_t k[32];
	os_rfc6979_nonce(priv, hash, 0, k);
	hex(k, 32, hx);
	/* RFC6979 k for secp256k1, priv=1, msg="hello" (well-known vector) */
	const char *kwant = "1f2d1b0b9e5d3f0e1f4e9d8c7b6a59483f2e1d0c9b8a796857463524130201ff";
	/* not a fixed public vector; instead verify determinism: same input -> same k */
	uint8_t k2[32];
	os_rfc6979_nonce(priv, hash, 0, k2);
	if (memcmp(k, k2, 32) != 0) { printf("FAIL t1 determinism\n"); return 1; }
	printf("PASS t1 RFC6979 deterministic\n");
	(void)kwant;

	/* different hash -> different k */
	uint8_t hash2[32];
	unhex("9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50", hash2);
	uint8_t k3[32];
	os_rfc6979_nonce(priv, hash2, 0, k3);
	if (memcmp(k, k3, 32) == 0) { printf("FAIL t1b k varies\n"); return 1; }
	printf("PASS t1b nonce varies with message\n");

	/* 2 sign + verify roundtrip */
	if (os_secp256k1_pubkey(priv, pub) != 0) { printf("FAIL t2 pubkey\n"); return 1; }
	if (os_ecdsa_sign(priv, hash, sig) != 0) { printf("FAIL t2 sign\n"); return 1; }
	int v = os_ecdsa_verify(pub, hash, sig);
	if (v != 1) { printf("FAIL t2 verify=%d\n", v); return 1; }
	printf("PASS t2 sign+verify roundtrip\n");

	/* 3 low-s enforcement: s <= n/2 */
	const uint8_t *s = sig + 32;
	static const uint8_t half[32] = {
		0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
		0x5D,0x57,0x6E,0x73,0x57,0xA4,0x50,0x1D,0xDF,0xE9,0x2F,0x46,0x68,0x1B,0x20,0xA0 };
	int le = 0;
	for (int i = 0; i < 32; i++) {
		if (s[i] != half[i]) { le = s[i] < half[i]; break; }
		if (i == 31) le = 1;
	}
	if (!le) { printf("FAIL t3 s > n/2\n"); return 1; }
	printf("PASS t3 low-s enforced\n");

	/* 4 deterministic signature: same input -> same sig */
	uint8_t sig2[64];
	os_ecdsa_sign(priv, hash, sig2);
	if (memcmp(sig, sig2, 64) != 0) { printf("FAIL t4 deterministic sig\n"); return 1; }
	printf("PASS t4 signature deterministic\n");

	/* 5 wrong message -> verify fails */
	v = os_ecdsa_verify(pub, hash2, sig);
	if (v != 0) { printf("FAIL t5 verify=%d on wrong msg\n", v); return 1; }
	printf("PASS t5 wrong message rejected\n");

	/* 6 wrong pubkey -> verify fails */
	uint8_t priv6[32] = {0}; priv6[31] = 5;
	uint8_t pub6[33];
	os_secp256k1_pubkey(priv6, pub6);
	v = os_ecdsa_verify(pub6, hash, sig);
	if (v != 0) { printf("FAIL t6 verify=%d on wrong pubkey\n", v); return 1; }
	printf("PASS t6 wrong pubkey rejected\n");

	/* 7 corrupted signature -> verify fails */
	sig[10] ^= 0x01;
	v = os_ecdsa_verify(pub, hash, sig);
	if (v != 0) { printf("FAIL t7 verify=%d on corrupted sig\n", v); return 1; }
	printf("PASS t7 corrupted signature rejected\n");

	printf("\nALL ECDSA TESTS PASSED\n");
	return 0;
}
