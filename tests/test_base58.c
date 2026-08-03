/* base58check tests — known address vectors. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/base58.h"

#include "../core/hkdf.c"
#include "../core/base58.c"

int main(void)
{
	char out[40];

	/* 1 P2PKH: version 0x00 + hash160 0x010966776006953D5567439E5E39F86A0D273BEE
	 * -> known address 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM */
	uint8_t payload[20] = {
		0x01,0x09,0x66,0x77,0x60,0x06,0x95,0x3D,0x55,0x67,
		0x43,0x9E,0x5E,0x39,0xF8,0x6A,0x0D,0x27,0x3B,0xEE };
	size_t n = os_base58check_encode(0x00, payload, out, sizeof out);
	if (n == 0 || strcmp(out, "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM") != 0) {
		printf("FAIL t1 got %s\n", out); return 1; }
	printf("PASS t1 P2PKH address\n");

	/* 2 sha256d of empty */
	uint8_t h[32]; char hx[65];
	os_sha256d((const uint8_t *)"", 0, h);
	static const char *he = "0123456789abcdef";
	for (int i = 0; i < 32; i++) { hx[i*2]=he[h[i]>>4]; hx[i*2+1]=he[h[i]&0xf]; }
	hx[64]=0;
	const char *want = "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456";
	if (strcmp(hx, want) != 0) { printf("FAIL t2\n%s\n", hx); return 1; }
	printf("PASS t2 sha256d\n");

	printf("\nALL BASE58 TESTS PASSED\n");
	return 0;
}
