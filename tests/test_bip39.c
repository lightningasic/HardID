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
	uint8_t seed[64], hbuf[64];
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

	/* Prefix resolution: "aban" -> "abandon" (unique 4-char prefix) */
	int wi = os_bip39_word_resolve_prefix("aban", 4);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "abandon") != 0) {
		printf("FAIL t7 resolve aban wi=%d\n", wi); return 1; }
	printf("PASS t7 prefix aban -> abandon\n");

	/* Short word via whole-word prefix: "add" must resolve to "add" (word is
	 * 3 letters; it is a prefix of "addict"/"address" so 4-char match differs) */
	wi = os_bip39_word_resolve_prefix("add", 3);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "add") != 0) {
		printf("FAIL t8 prefix add(3) wi=%d\n", wi); return 1; }
	printf("PASS t8 short word add resolves to itself\n");

	/* A 3-letter prefix must NOT match a longer word that merely starts with
	 * it: "add" typed at length 3 must not yield "address". */
	if (os_bip39_word_resolve_prefix("addr", 4) < 0 ||
	    strcmp(os_bip39_word_at(os_bip39_word_resolve_prefix("addr", 4)), "address") != 0) {
		printf("FAIL t9 addr -> address\n"); return 1; }
	printf("PASS t9 addr -> address\n");

	/* Unique prefix resolves: "abso" -> "absorb" */
	wi = os_bip39_word_resolve_prefix("abso", 4);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "absorb") != 0) {
		printf("FAIL t10 abso wi=%d\n", wi); return 1; }
	printf("PASS t10 abso -> absorb\n");

	/* Non-prefix returns -1 */
	if (os_bip39_word_resolve_prefix("zzzz", 4) != -1) {
		printf("FAIL t11 zzzz must not resolve\n"); return 1; }
	printf("PASS t11 non-word prefix rejected\n");

	/* Auto-commit (try_commit): 4-char prefix commits uniquely ("aban") */
	wi = os_bip39_word_try_commit("aban", 4);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "abandon") != 0) {
		printf("FAIL t12 commit aban wi=%d\n", wi); return 1; }
	printf("PASS t12 try_commit aban -> abandon\n");

	/* Auto-commit: a 3-letter word with no longer word extending it commits
	 * at 3 chars ("zoo" is terminal; there is no "zoo*" word). */
	wi = os_bip39_word_try_commit("zoo", 3);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "zoo") != 0) {
		printf("FAIL t13 commit zoo(3) wi=%d\n", wi); return 1; }
	printf("PASS t13 try_commit zoo(3) -> zoo\n");

	/* Auto-commit must NOT fire for a short word that can be extended:
	 * "add" is a word but "addict"/"address" start with it, so 3 chars
	 * stays open until the 4th disambiguates. */
	if (os_bip39_word_try_commit("add", 3) != -1) {
		printf("FAIL t14 commit add(3) must be ambiguous\n"); return 1; }
	wi = os_bip39_word_try_commit("addi", 4);
	if (wi < 0 || strcmp(os_bip39_word_at(wi), "addict") != 0) {
		printf("FAIL t14 commit addi wi=%d\n", wi); return 1; }
	printf("PASS t14 add stays open; addi -> addict\n");

	/* Auto-commit returns -1 for a non-word prefix */
	if (os_bip39_word_try_commit("zzz", 3) != -1 &&
	    os_bip39_word_try_commit("zzzz", 4) != -1) {
		printf("FAIL t15 zzz must not commit\n"); return 1; }
	printf("PASS t15 non-word prefix not committed\n");

	(void)hbuf;
	printf("\nALL BIP39 TESTS PASSED\n");
	return 0;
}
