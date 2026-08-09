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

	/* 8 fixed KDF vector — locks the HardID two-step passphrase derivation
	 * so third-party recovery tooling has a published reference:
	 *   base = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048)   (BIP39 std)
	 *   sess = PBKDF2-HMAC-SHA512(base, "mnemonic"+pass, 2048)  (HardID spec)
	 * mnemonic = "abandon"x11 + "about" (official BIP39 vector for base),
	 * pass = "HardCase9!" (upper+lower+digit+symbol charset).
	 * The mock sig encodes the active key: sig[i] = digest[i%32] ^ k[i] ^ i,
	 * so with a zero digest, k[i] = sig[i] ^ i. */
	se_mock_reset();
	{
		static const uint8_t base_v[64] = {
			0x5e,0xb0,0x0b,0xbd,0xdc,0xf0,0x69,0x08,
			0x48,0x89,0xa8,0xab,0x91,0x55,0x56,0x81,
			0x65,0xf5,0xc4,0x53,0xcc,0xb8,0x5e,0x70,
			0x81,0x1a,0xae,0xd6,0xf6,0xda,0x5f,0xc1,
			0x9a,0x5a,0xc4,0x0b,0x38,0x9c,0xd3,0x70,
			0xd0,0x86,0x20,0x6d,0xec,0x8a,0xa6,0xc4,
			0x3d,0xae,0xa6,0x69,0x0f,0x20,0xad,0x3d,
			0x8d,0x48,0xb2,0xd2,0xce,0x9e,0x38,0xe4,
		};
		static const uint8_t sess_v[64] = {
			0xfc,0xd3,0xf7,0x04,0x7d,0x4a,0x21,0xd5,
			0xda,0xb3,0xe0,0x99,0x05,0x35,0xcf,0xcd,
			0xfd,0xff,0xf7,0x36,0x7e,0x0c,0x40,0x68,
			0x85,0x67,0xbd,0x5f,0x4d,0xaf,0xf6,0x78,
			0xb0,0xad,0x06,0x18,0x4e,0xb5,0xdc,0xf4,
			0x0d,0x91,0x30,0x73,0xbc,0x67,0xd6,0xdd,
			0xe5,0x69,0xf4,0xcf,0x9e,0x2e,0x93,0x31,
			0x9f,0x3f,0x67,0xcf,0xdd,0x68,0x6a,0x5d,
		};
		if (se->store_seed(base_v) != SE_OK) { printf("FAIL t8 store\n"); return 1; }
		se_mock_set_pin(pin, 4);
		if (se->verify_pin(pin, 4, NULL, NULL) != SE_OK) { printf("FAIL t8 pin\n"); return 1; }
		const uint8_t pw[10] = {'H','a','r','d','C','a','s','e','9','!'};
		if (se->derive_session(pw, 10) != SE_OK) { printf("FAIL t8 derive\n"); return 1; }
		uint8_t z[32] = {0}, sg[64], rec[64];
		if (se->sign_digest(NULL, 0, z, sg, NULL) != SE_OK) { printf("FAIL t8 sign\n"); return 1; }
		for (int i = 0; i < 64; i++) rec[i] = sg[i] ^ (uint8_t)i;
		if (memcmp(rec, sess_v, 64) != 0) { printf("FAIL t8 KDF vector mismatch\n"); return 1; }
	}
	printf("PASS t8 passphrase KDF fixed vector\n");

	printf("\nALL SE MOCK TESTS PASSED\n");
	return 0;
}
