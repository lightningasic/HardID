/* Verify the unconditional entropy pool: mixing properties + single-use. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/phys_entropy.h"

#define OS_RNG_NO_DEFAULT_FATAL
#include "../core/hkdf.c"        /* os_sha256 */

int main(void)
{
	uint8_t a[32], b[32], c[32];
	os_phys_pool_t p1, p2;

	/* deterministic given same inputs */
	os_phys_pool_init(&p1);
	os_phys_pool_init(&p2);
	os_phys_pool_absorb(&p1, (const uint8_t *)"abc", 3);
	os_phys_pool_absorb(&p1, (const uint8_t *)"def", 3);
	os_phys_pool_absorb(&p2, (const uint8_t *)"abc", 3);
	os_phys_pool_absorb(&p2, (const uint8_t *)"def", 3);
	os_phys_pool_extract(&p1, a, 32);
	os_phys_pool_extract(&p2, b, 32);
	if (memcmp(a, b, 32) != 0) { printf("FAIL determinism\n"); return 1; }
	printf("PASS deterministic given same inputs\n");

	/* adding a source changes output */
	os_phys_pool_init(&p1);
	os_phys_pool_absorb(&p1, (const uint8_t *)"abc", 3);
	os_phys_pool_absorb(&p1, (const uint8_t *)"XYZ", 3);
	os_phys_pool_extract(&p1, c, 32);
	if (memcmp(a, c, 32) == 0) { printf("FAIL source changes output\n"); return 1; }
	printf("PASS extra source changes output\n");

	/* prefix-safety: absorb("abc") then absorb("def") != absorb("abcdef") */
	os_phys_pool_init(&p1);
	os_phys_pool_absorb(&p1, (const uint8_t *)"abc", 3);
	os_phys_pool_absorb(&p1, (const uint8_t *)"def", 3);
	os_phys_pool_extract(&p1, a, 32);
	os_phys_pool_init(&p2);
	os_phys_pool_absorb(&p2, (const uint8_t *)"abcdef", 6);
	os_phys_pool_extract(&p2, b, 32);
	if (memcmp(a, b, 32) == 0) { printf("FAIL prefix-safety\n"); return 1; }
	printf("PASS prefix-safe (abc|def != abcdef)\n");

	/* single-use: extracting twice gives fixed zero (not the pool again) */
	os_phys_pool_init(&p1);
	os_phys_pool_absorb(&p1, (const uint8_t *)"data", 4);
	os_phys_pool_extract(&p1, a, 32);
	os_phys_pool_extract(&p1, b, 32);
	if (memcmp(b, (uint8_t[32]){0}, 32) != 0) { printf("FAIL single-use\n"); return 1; }
	printf("PASS single-use (second extract yields zero)\n");

	/* empty pool still yields deterministic output */
	os_phys_pool_init(&p1);
	os_phys_pool_extract(&p1, a, 32);
	os_phys_pool_init(&p2);
	os_phys_pool_extract(&p2, b, 32);
	if (memcmp(a, b, 32) != 0) { printf("FAIL empty pool determinism\n"); return 1; }
	printf("PASS empty pool deterministic\n");

	printf("\nALL PHYS_ENTROPY TESTS PASSED\n");
	return 0;
}
