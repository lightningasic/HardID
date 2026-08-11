/* secp256r1 (P-256) ECDSA tests — RFC6979 A.2.5 vectors + roundtrip. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/secp256r1.h"
#include "../core/rfc6979.h"

#include "../core/hkdf.c"
#include "../core/rfc6979.c"
#include "../core/secp256r1.c"

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

/* RFC 6979 A.2.5 P-256 private key + derived public point */
static const char *RFC_PRIV = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
static const char *RFC_UX  = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
static const char *RFC_UY  = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";
static const char *NBE     = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551";

static int memeq(const uint8_t *a, const uint8_t *b, size_t n) { return memcmp(a,b,n)==0; }

int main(void)
{
	uint8_t priv[32], hash[32], pub[65], sig[64];
	char hx[400];
	uint8_t nbe[32];
	unhex(NBE, nbe);

	/* 1 RFC6979 known-answer: k for P-256, RFC priv, SHA256("sample") */
	unhex(RFC_PRIV, priv);
	unhex("af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf", hash); /* sha256("sample") */
	uint8_t k[32], kwant[32];
	unhex("A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60", kwant);
	if (os_rfc6979_nonce_n(nbe, priv, hash, 0, k) != 0) { printf("FAIL t1 nonce\n"); return 1; }
	if (!memeq(k, kwant, 32)) { hex(k, 32, hx); hex(kwant, 32, hx+70);
		printf("FAIL t1 nonce k=%s want=%s\n", hx, hx+70); return 1; }
	printf("PASS t1 RFC6979 P-256 k vector (SHA256 sample)\n");

	/* 2 public key KAT: RFC priv -> RFC Ux||Uy (uncompressed 65 bytes) */
	uint8_t ux[32], uy[32], want65[65];
	unhex(RFC_UY, uy);
	if (os_secp256r1_pubkey(priv, pub) != 0) { printf("FAIL t2 pubkey\n"); return 1; }
	unhex(RFC_UX, ux);
	want65[0] = 0x04;
	memcpy(want65+1, ux, 32); memcpy(want65+33, uy, 32);
	if (!memeq(pub, want65, 65)) {
		hex(pub, 65, hx); hex(want65, 65, hx+140);
		printf("FAIL t2 pub=%s want=%s\n", hx, hx+140); return 1;
	}
	printf("PASS t2 P-256 pubkey KAT (uncompressed 65B)\n");

	/* 3 sign KAT: r must equal RFC r for SHA256("sample"); s is low-s
	 * normalized (RFC s is high-s, > n/2) */
	uint8_t rwant[32], swant[32];
	unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", rwant);
	unhex("0834E36AD29A83BF2BC9385E491D6099C8FDF9D1ED67AA7EA5F51F93782857A9", swant); /* n - RFC s */
	if (os_secp256r1_sign(priv, hash, sig) != 0) { printf("FAIL t3 sign\n"); return 1; }
	if (!memeq(sig, rwant, 32) || !memeq(sig+32, swant, 32)) {
		hex(sig, 64, hx); hex(rwant, 32, hx+140); hex(swant, 32, hx+210);
		printf("FAIL t3 sig=%s rwant=%s swant=%s\n", hx, hx+140, hx+210); return 1;
	}
	printf("PASS t3 sign KAT (RFC6979 SHA256 sample, low-s)\n");

	/* 4 verify the raw RFC signature (high-s) and our low-s signature */
	uint8_t raw_sig[64];
	unhex("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716", raw_sig);
	unhex("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8", raw_sig+32);
	int v = os_secp256r1_verify(pub, 65, hash, raw_sig);
	if (v != 1) { printf("FAIL t4a verify raw RFC sig=%d\n", v); return 1; }
	v = os_secp256r1_verify(pub, 65, hash, sig);
	if (v != 1) { printf("FAIL t4b verify own sig=%d\n", v); return 1; }
	printf("PASS t4 verify raw RFC (high-s) + own sig\n");

	/* 5 compressed pubkey accepted + verify (exercises fe_sqrt) */
	uint8_t pub33[33];
	pub33[0] = (uy[31] & 1) ? 0x03 : 0x02;
	memcpy(pub33+1, ux, 32);
	v = os_secp256r1_verify(pub33, 33, hash, sig);
	if (v != 1) { printf("FAIL t5 verify compressed pub=%d\n", v); return 1; }
	/* parse both forms and scalar-multiply back to the RFC public point */
	uint8_t pt[OS_SECP256R1_POINT_SIZE], out65[65], one32[32] = {0};
	one32[31] = 1;
	if (os_secp256r1_parse_pubkey(pub33, 33, pt) != 0) { printf("FAIL t5 parse33\n"); return 1; }
	if (os_secp256r1_point_mul(pt, one32, out65) != 0) { printf("FAIL t5 pmul\n"); return 1; }
	if (!memeq(pub, out65, 65)) { printf("FAIL t5 1*pub roundtrip\n"); return 1; }
	printf("PASS t5 compressed pubkey + parse/mul roundtrip\n");

	/* 6 W-NAF-free check: 2G via point_add(G,G) == pubkey(2) */
	uint8_t two[32] = {0}; two[31] = 2;
	uint8_t pub2[65];
	if (os_secp256r1_pubkey(two, pub2) != 0) { printf("FAIL t6 pubkey2\n"); return 1; }
	uint8_t gpt[OS_SECP256R1_POINT_SIZE], gpub[65];
	unhex("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296", ux);
	unhex("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5", uy);
	uint8_t g33[33]; g33[0] = (uy[31] & 1) ? 0x03 : 0x02; memcpy(g33+1, ux, 32);
	if (os_secp256r1_parse_pubkey(g33, 33, gpt) != 0) { printf("FAIL t6 parseG\n"); return 1; }
	if (os_secp256r1_point_add(gpt, gpt, gpub) != 0) { printf("FAIL t6 G+G\n"); return 1; }
	if (!memeq(gpub, pub2, 65)) { printf("FAIL t6 G+G != 2G\n"); return 1; }
	printf("PASS t6 point_add(G,G) == 2G\n");

	/* 7 scalar ops: add commutative, mul commutative, inv(a)*a == 1 */
	uint8_t a[32], b[32], c[32], d[32], one[32] = {0};
	unhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF", a);
	unhex("FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210", b);
	memcpy(c, sig, 32); /* arbitrary well-formed scalar */
	one[31] = 1;
	os_secp256r1_scalar_add(d, a, b);
	os_secp256r1_scalar_add(c, b, a);
	if (!memeq(d, c, 32)) { printf("FAIL t7 add commut\n"); return 1; }
	os_secp256r1_scalar_mul(d, a, b);
	os_secp256r1_scalar_mul(c, b, a);
	if (!memeq(d, c, 32)) { printf("FAIL t7 mul commut\n"); return 1; }
	uint8_t inva[32];
	if (os_secp256r1_scalar_inv(inva, a) != 0) { printf("FAIL t7 inv\n"); return 1; }
	os_secp256r1_scalar_mul(d, inva, a);
	if (!memeq(d, one, 32)) { printf("FAIL t7 inv(a)*a != 1\n"); return 1; }
	printf("PASS t7 scalar add/mul/inv\n");

	/* 8 roundtrip across keys 1..5 x two messages */
	for (uint8_t i = 1; i <= 5; i++) {
		uint8_t pk[32] = {0}; pk[31] = i;
		uint8_t pkub[65], hs[32];
		if (os_secp256r1_pubkey(pk, pkub) != 0) { printf("FAIL t8 pubkey %u\n", i); return 1; }
		if (os_secp256r1_sign(pk, hash, sig) != 0) { printf("FAIL t8 sign %u\n", i); return 1; }
		if (os_secp256r1_verify(pkub, 65, hash, sig) != 1) { printf("FAIL t8 verify %u\n", i); return 1; }
		unhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hs); /* sha256("test") */
		if (os_secp256r1_sign(pk, hs, sig) != 0) { printf("FAIL t8 sign2 %u\n", i); return 1; }
		if (os_secp256r1_verify(pkub, 65, hs, sig) != 1) { printf("FAIL t8 verify2 %u\n", i); return 1; }
	}
	printf("PASS t8 sign/verify roundtrip (keys 1-5, two messages)\n");

	/* 9 malformed inputs rejected */
	uint8_t zero[32] = {0};
	uint8_t badpub[65] = {0x04, 0x01};
	uint8_t zerosig[64] = {0};
	if (os_secp256r1_pubkey(zero, pub) == 0) { printf("FAIL t9 pubkey(0)\n"); return 1; }
	if (os_secp256r1_pubkey(nbe, pub) == 0) { printf("FAIL t9 pubkey(n)\n"); return 1; }
	v = os_secp256r1_verify(pub, 65, hash, zerosig); /* all-zero sig */
	if (v != -1) { printf("FAIL t9 verify zero sig=%d\n", v); return 1; }
	if (os_secp256r1_verify(badpub, 65, hash, sig) != -1) { printf("FAIL t9 verify bad pub\n"); return 1; }
	if (os_secp256r1_verify(pub, 64, hash, sig) != -1) { printf("FAIL t9 verify bad len\n"); return 1; }
	printf("PASS t9 malformed inputs rejected\n");

	/* 10 wrong message / corrupted sig rejected */
	unhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", hash);
	v = os_secp256r1_verify(pub, 65, hash, sig);
	if (v != 0) { printf("FAIL t10 wrong msg=%d\n", v); return 1; }
	sig[20] ^= 0x80;
	v = os_secp256r1_verify(pub, 65, hash, sig);
	if (v != 0) { printf("FAIL t10 corrupted sig=%d\n", v); return 1; }
	printf("PASS t10 wrong message / corrupted sig rejected\n");

	printf("\nALL SECP256R1 TESTS PASSED\n");
	return 0;
}