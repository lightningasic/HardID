/* SE mock backend tests. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/se_driver.h"

#include "../core/sha512.c"
#include "../core/se_mock.c"

int main(void)
{
	const se_driver_t *se = se_active();

	/* 1 lifecycle: uninitialized -> store -> initialized, double-store rejected */
	se_mock_reset();
	bool init = true;
	se->is_initialized(&init);
	if (init) { printf("FAIL t1 pre-init\n"); return 1; }
	uint8_t seed[64]; memset(seed, 0x11, 64);
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

	/* 7 derive_session: base seed signs base sig; a passphrase folds into a
	 * different session sig; empty passphrase returns to base. */
	uint8_t sig_base[64], sig_pp[64], sig_pp2[64], sig_back[64];
	if (se->derive_session(NULL, 0) != SE_OK) { printf("FAIL t7 clear\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig_base, NULL) != SE_OK) { printf("FAIL t7 base sign\n"); return 1; }
	const uint8_t pp[5] = {'h','u','n','t','e'};
	if (se->derive_session(pp, 5) != SE_OK) { printf("FAIL t7 derive\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig_pp, NULL) != SE_OK) { printf("FAIL t7 pp sign\n"); return 1; }
	if (memcmp(sig_pp, sig_base, 64) == 0) { printf("FAIL t7 pp != base\n"); return 1; }
	/* same passphrase is deterministic */
	if (se->derive_session(pp, 5) != SE_OK) { printf("FAIL t7 rederive\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig_pp2, NULL) != SE_OK) { printf("FAIL t7 pp2 sign\n"); return 1; }
	if (memcmp(sig_pp, sig_pp2, 64) != 0) { printf("FAIL t7 pp determinism\n"); return 1; }
	/* different passphrase => different sig */
	const uint8_t pp2[5] = {'t','o','o','r','y'};
	if (se->derive_session(pp2, 5) != SE_OK) { printf("FAIL t7 derive2\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig_pp2, NULL) != SE_OK) { printf("FAIL t7 derive2 sign\n"); return 1; }
	if (memcmp(sig_pp2, sig_pp, 64) == 0) { printf("FAIL t7 differ\n"); return 1; }
	/* empty clears back to base */
	if (se->derive_session(NULL, 0) != SE_OK) { printf("FAIL t7 clear2\n"); return 1; }
	if (se->sign_digest(NULL, 0, digest, sig_back, NULL) != SE_OK) { printf("FAIL t7 back sign\n"); return 1; }
	if (memcmp(sig_back, sig_base, 64) != 0) { printf("FAIL t7 back == base\n"); return 1; }
	/* derive before provisioning is refused */
	se_mock_reset();
	if (se->derive_session(pp, 5) != SE_ERR_STATE) { printf("FAIL t7 derive-before-store\n"); return 1; }
	printf("PASS t7 passphrase session derive\n");

	printf("\nALL SE MOCK TESTS PASSED\n");
	return 0;
}
