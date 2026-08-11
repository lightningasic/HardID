/* Verify multi-source seed generation: determinism + source isolation. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/rng.h"
#include "../core/seed.h"

/* deterministic fake RNG */
static uint32_t seq;
static uint8_t se_bytes[32];

uint32_t os_rng_hw_read_status(void) { return 1; }
uint32_t os_rng_hw_read_data(void) { return seq++ * 2654435761u; }
void os_rng_hw_recover(void) {}
void os_rng_fatal(void) { printf("unexpected fatal\n"); }
int os_seed_se_trng(uint8_t *buf, size_t len)
{
	memcpy(buf, se_bytes, len < 32 ? len : 32);
	return 0;
}
/* second source uses the fake MCU rng (exercises the fallback path) */
int os_seed_se2_trng(uint8_t *buf, size_t len)
{
	os_rng_fill(buf, len);
	return 0;
}

/* no physical entropy in the host test build (optional Layer A hook) */
int os_seed_phys_extra(uint8_t *buf, size_t len)
{
	(void)buf; (void)len;
	return 1;
}

#define OS_RNG_NO_DEFAULT_FATAL
#include "../core/rng.c"
#include "../core/hkdf.c"
#define OS_SEED_NO_DEFAULT_HOOK
#include "../core/seed.c"

int main(void)
{
	uint8_t seed1[32], seed2[32];
	memset(se_bytes, 0xA5, 32);

	/* same inputs -> same seed (deterministic given same entropy) */
	seq = 1;
	os_seed_generate((const uint8_t *)"hostA", 5, seed1);
	seq = 1;
	os_seed_generate((const uint8_t *)"hostA", 5, seed2);
	if (memcmp(seed1, seed2, 32) != 0) { printf("FAIL determinism\n"); return 1; }
	printf("PASS deterministic given same entropy\n");

	/* different host entropy -> different seed */
	seq = 1;
	os_seed_generate((const uint8_t *)"hostB", 5, seed2);
	if (memcmp(seed1, seed2, 32) == 0) { printf("FAIL host entropy isolation\n"); return 1; }
	printf("PASS host entropy changes seed\n");

	/* different SE entropy -> different seed */
	memset(se_bytes, 0x5A, 32);
	seq = 1;
	os_seed_generate((const uint8_t *)"hostA", 5, seed2);
	if (memcmp(seed1, seed2, 32) == 0) { printf("FAIL SE entropy isolation\n"); return 1; }
	printf("PASS SE entropy changes seed\n");

	/* no host entropy still works */
	seq = 1;
	if (os_seed_generate(NULL, 0, seed2) != 0) { printf("FAIL no-host\n"); return 1; }
	printf("PASS works without host entropy\n");

	printf("\nALL SEED TESTS PASSED\n");
	return 0;
}
