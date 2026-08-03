/* BIP39 tests — official test vectors (Trezor's published set). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/bip39.h"
#include "../core/sha512.h"

#include "../core/sha512.c"
#include "../core/hkdf.c"   /* provides os_sha256 via sha256.h */
#include "../core/bip39.c"

static void hex(const uint8_t *d, size_t n, char *o)
{
	static const char *h = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { o[i*2]=h[d[i]>>4]; o[i*2+1]=h[d[i]&0xf]; }
	o[n*2]=0;
}
static size_t unhex(const char *s, uint8_t *out)
{
	size_t n = 0;
	while (s[0] && s[1]) {
		unsigned v; sscanf(s, "%2x", &v);
		out[n++] = (uint8_t)v; s += 2;
	}
	return n;
}

int main(void)
{
	char m[OS_BIP39_MNEMONIC_MAX];
	uint8_t ent[32], seed[64], hbuf[64];
	char hx[129];

	/* Vector 1: entropy 00000000000000000000000000000000 ->
	 * "abandon abandon ... about" (12 words) */
	uint8_t e0[16] = {0};
	int w = os_bip39_entropy_to_mnemonic(e0, 16, m, sizeof m);
	const char *want1 = "abandon abandon abandon abandon abandon abandon "
		"abandon abandon abandon abandon abandon about";
	if (w != 12 || strcmp(m, want1) != 0) { printf("FAIL t1 w=%d\n%s\n", w, m); return 1; }
	printf("PASS t1 entropy->mnemonic (12 words)\n");

	/* seed with passphrase "TREZOR" — official vector */
	os_bip39_mnemonic_to_seed(m, "TREZOR", seed);
	hex(seed, 64, hx);
	const char *seed1 = "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531"
		"f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04";
	if (strcmp(hx, seed1) != 0) { printf("FAIL t1 seed\n%s\n", hx); return 1; }
	printf("PASS t1 mnemonic->seed (BIP39 vector)\n");

	/* Vector 2: entropy 7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f -> "legal winner thank..." */
	uint8_t e1[16];
	unhex("7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f", e1);
	w = os_bip39_entropy_to_mnemonic(e1, 16, m, sizeof m);
	const char *want2 = "legal winner thank year wave sausage worth useful legal winner thank yellow";
	if (w != 12 || strcmp(m, want2) != 0) { printf("FAIL t2\n%s\n", m); return 1; }
	printf("PASS t2 second vector\n");

	/* Round-trip: mnemonic -> entropy */
	uint8_t rec[32];
	size_t rl = os_bip39_mnemonic_to_entropy(m, rec, sizeof rec);
	if (rl != 16 || memcmp(rec, e1, 16) != 0) { printf("FAIL t3 roundtrip rl=%zu\n", rl); return 1; }
	printf("PASS t3 mnemonic->entropy roundtrip\n");

	/* Vector 3: 24 words — entropy ff..ff (32 bytes) -> "zoo" x23 + "vote" */
	uint8_t e2[32]; memset(e2, 0xff, 32);
	w = os_bip39_entropy_to_mnemonic(e2, 32, m, sizeof m);
	if (w != 24) { printf("FAIL t4 words=%d\n", w); return 1; }
	/* check first and last word */
	if (strncmp(m, "zoo", 3) != 0 || strcmp(m + strlen(m) - 4, "vote") != 0) {
		printf("FAIL t4\n%s\n", m); return 1; }
	printf("PASS t4 24-word mnemonic\n");

	/* Invalid checksum rejected */
	char bad[OS_BIP39_MNEMONIC_MAX];
	strcpy(bad, m);
	bad[strlen(bad)-5] = 'x'; /* corrupt last word "vote" -> "xote"? */
	if (os_bip39_mnemonic_to_entropy("abandon abandon abandon abandon abandon abandon "
		"abandon abandon abandon abandon abandon abandon", rec, sizeof rec) != 0) {
		printf("FAIL t5 bad checksum accepted\n"); return 1; }
	printf("PASS t5 bad checksum rejected\n");

	/* Invalid word rejected */
	if (os_bip39_mnemonic_to_entropy("notaword abandon abandon abandon abandon abandon "
		"abandon abandon abandon abandon abandon about", rec, sizeof rec) != 0) {
		printf("FAIL t6 bad word accepted\n"); return 1; }
	printf("PASS t6 invalid word rejected\n");

	(void)hbuf;
	printf("\nALL BIP39 TESTS PASSED\n");
	return 0;
}
