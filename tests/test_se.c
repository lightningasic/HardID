/* SE mock backend tests. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/se_driver.h"

#include "../core/se_mock.c"

int main(void)
{
	const se_driver_t *se = se_active();

	/* 1 lifecycle: uninitialized -> store -> initialized, double-store rejected */
	se_mock_reset();
	bool init = true;
	se->is_initialized(&init);
	if (init) { printf("FAIL t1 pre-init\n"); return 1; }
	uint8_t seed[32]; memset(seed, 0x11, 32);
	if (se->store_seed(seed) != SE_OK) { printf("FAIL t1 store\n"); return 1; }
	if (se->store_seed(seed) != SE_ERR_STATE) { printf("FAIL t1 double-store\n"); return 1; }
	se->is_initialized(&init);
	if (!init) { printf("FAIL t1 post-init\n"); return 1; }
	printf("PASS t1 seed lifecycle\n");

	/* 2 TRNG produces bytes and advances */
	uint8_t a[16], b[16];
	se->get_random(a, 16);
	se->get_random(b, 16);
	if (memcmp(a, b, 16) == 0) { printf("FAIL t2 rng stagnant\n"); return 1; }
	printf("PASS t2 TRNG advances\n");

	/* 3 signing requires the session to be unlocked by verify_pin first */
	uint8_t digest[32]; memset(digest, 0x22, 32);
	uint8_t sig1[64], sig2[64];
	/* locked: must be refused */
	if (se->sign_digest(NULL, 0, digest, sig1, NULL) != SE_ERR_AUTH) {
		printf("FAIL t3 sign while locked not refused\n"); return 1; }
	printf("PASS t3a sign while locked refused\n");
	/* unlock, then sign */
	uint8_t pin[4] = {'1','2','3','4'};
	se_mock_set_pin(pin, 4);
	if (se->verify_pin(pin, 4, NULL, NULL) != SE_OK) { printf("FAIL t3 unlock\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig1, NULL) != SE_OK) { printf("FAIL t3 sign\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig2, NULL) != SE_OK) { printf("FAIL t3 sign2\n"); return 1; }
	if (memcmp(sig1, sig2, 64) != 0) { printf("FAIL t3 determinism\n"); return 1; }
	printf("PASS t3 sign determinism after unlock\n");

	/* 4 PIN verify (already set above) */
	uint8_t wrong[4] = {'9','9','9','9'};
	if (se->verify_pin(wrong, 4, NULL, NULL) != SE_ERR_AUTH) { printf("FAIL t4 wrong pin\n"); return 1; }
	if (se->verify_pin(pin, 4, NULL, NULL) != SE_OK) { printf("FAIL t4 pin\n"); return 1; }
	printf("PASS t4 PIN verify\n");

	/* 5 monotonic counter */
	uint32_t c0, c1;
	se->monotonic_read(&c0);
	se->monotonic_increment();
	se->monotonic_read(&c1);
	if (c1 != c0 + 1) { printf("FAIL t5\n"); return 1; }
	printf("PASS t5 monotonic counter\n");

	/* 6 policy default = manual confirm */
	if (se->policy_authorize(0, 100) != SE_ERR_AUTH) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 policy defaults to manual\n");

	printf("\nALL SE MOCK TESTS PASSED\n");
	return 0;
}
