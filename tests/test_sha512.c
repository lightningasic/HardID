/* SHA-512, HMAC-SHA512, PBKDF2-SHA512 tests — official vectors. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/sha512.h"

#include "../core/sha512.c"

static void hex(const uint8_t *d, size_t n, char *o)
{
	static const char *h = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { o[i*2]=h[d[i]>>4]; o[i*2+1]=h[d[i]&0xf]; }
	o[n*2]=0;
}

int main(void)
{
	uint8_t out[64]; char h[129];

	/* 1 sha512("abc") — FIPS 180-4 */
	os_sha512((const uint8_t *)"abc", 3, out);
	hex(out, 64, h);
	const char *abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
		"2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
	if (strcmp(h, abc) != 0) { printf("FAIL t1\n%s\n", h); return 1; }
	printf("PASS t1 sha512 abc\n");

	/* 2 sha512("") */
	os_sha512((const uint8_t *)"", 0, out);
	hex(out, 64, h);
	const char *empty = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
	if (strcmp(h, empty) != 0) { printf("FAIL t2\n"); return 1; }
	printf("PASS t2 sha512 empty\n");

	/* 3 HMAC-SHA512 RFC 4231 TC1 (key=0x0b*20, "Hi There") */
	{
		uint8_t key[20]; memset(key, 0x0b, 20);
		os_hmac_sha512(key, 20, (const uint8_t *)"Hi There", 8, out);
		hex(out, 64, h);
		const char *hm = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
			"daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
		if (strcmp(h, hm) != 0) { printf("FAIL t3\n%s\n", h); return 1; }
		printf("PASS t3 hmac-sha512 RFC4231\n");
	}

	/* 4 PBKDF2-SHA512 (BIP39 uses this): P="password", S="salt", c=1, dkLen=64 */
	{
		os_pbkdf2_sha512((const uint8_t *)"password", 8,
		                 (const uint8_t *)"salt", 4, 1, out, 64);
		hex(out, 64, h);
		const char *pb = "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252"
			"c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce";
		if (strcmp(h, pb) != 0) { printf("FAIL t4\n%s\n", h); return 1; }
		printf("PASS t4 pbkdf2-sha512 c=1\n");
	}

	printf("\nALL SHA512 TESTS PASSED\n");
	return 0;
}
