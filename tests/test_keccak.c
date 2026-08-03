/* Keccak-256 tests: official vectors + EIP-55 checksum. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/keccak.h"

#include "../core/keccak.c"

static void to_hex(const uint8_t *d, size_t n, char *out)
{
	static const char *h = "0123456789abcdef";
	for (size_t i = 0; i < n; i++) { out[i*2]=h[d[i]>>4]; out[i*2+1]=h[d[i]&0xf]; }
	out[n*2]=0;
}

int main(void)
{
	uint8_t out[32]; char hex[65];

	/* 1 keccak256("") — well-known constant */
	os_keccak256((const uint8_t *)"", 0, out);
	to_hex(out, 32, hex);
	const char *empty = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
	if (strcmp(hex, empty) != 0) { printf("FAIL t1\n%s\n", hex); return 1; }
	printf("PASS t1 keccak256 empty\n");

	/* 2 keccak256("abc") */
	os_keccak256((const uint8_t *)"abc", 3, out);
	to_hex(out, 32, hex);
	const char *abc = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
	if (strcmp(hex, abc) != 0) { printf("FAIL t2\n%s\n", hex); return 1; }
	printf("PASS t2 keccak256 abc\n");

	/* 3 streaming vs one-shot equivalence */
	{
		os_keccak_ctx c;
		os_keccak256_init(&c);
		os_keccak256_update(&c, (const uint8_t *)"a", 1);
		os_keccak256_update(&c, (const uint8_t *)"bc", 2);
		uint8_t s[32];
		os_keccak256_final(&c, s);
		if (memcmp(s, out, 32) != 0) { printf("FAIL t3\n"); return 1; }
		printf("PASS t3 streaming == one-shot\n");
	}

	/* 4 EIP-55 checksum — official example */
	{
		uint8_t addr[20];
		const char *in = "52908400098527886e0f7030069857d2e4169ee7";
		for (int i = 0; i < 20; i++) {
			unsigned v;
			sscanf(in + i*2, "%2x", &v);
			addr[i] = v;
		}
		char a[43];
		os_eth_address_checksum(addr, a);
		const char *want = "0x52908400098527886E0F7030069857D2E4169EE7";
		if (strcmp(a, want) != 0) { printf("FAIL t4\n got %s\nwant %s\n", a, want); return 1; }
		printf("PASS t4 EIP-55 checksum\n");
	}

	/* 5 EIP-55 all-caps example */
	{
		uint8_t addr[20];
		const char *in = "8617e340b3d01fa5f11f306f4090fd50e238070d";
		for (int i = 0; i < 20; i++) {
			unsigned v;
			sscanf(in + i*2, "%2x", &v);
			addr[i] = v;
		}
		char a[43];
		os_eth_address_checksum(addr, a);
		const char *want = "0x8617E340B3D01FA5F11F306F4090FD50E238070D";
		if (strcmp(a, want) != 0) { printf("FAIL t5\n got %s\nwant %s\n", a, want); return 1; }
		printf("PASS t5 EIP-55 all-caps\n");
	}

	printf("\nALL KECCAK TESTS PASSED\n");
	return 0;
}
