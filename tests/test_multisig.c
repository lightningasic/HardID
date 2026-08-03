/* Multisig config tests. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/multisig.h"

#include "../core/multisig.c"

static void mkfp(uint8_t fp[4], uint8_t seed)
{
	fp[0]=seed; fp[1]=seed+1; fp[2]=seed+2; fp[3]=seed+3;
}

int main(void)
{
	os_multisig m;
	memset(&m, 0, sizeof m);
	m.threshold_m = 2;
	m.total_n = 3;
	m.script = OS_MS_P2WSH;
	m.self_index = 0;
	mkfp(m.cosigner_fp[0], 10);
	mkfp(m.cosigner_fp[1], 20);
	mkfp(m.cosigner_fp[2], 30);

	/* 1 valid 2-of-3 */
	if (os_ms_validate(&m) != 0) { printf("FAIL t1\n"); return 1; }
	printf("PASS t1 valid 2-of-3\n");

	/* 2 M > N rejected */
	m.threshold_m = 4;
	if (os_ms_validate(&m) == 0) { printf("FAIL t2\n"); return 1; }
	m.threshold_m = 2;
	printf("PASS t2 M>N rejected\n");

	/* 3 duplicate fingerprints rejected */
	mkfp(m.cosigner_fp[2], 10); /* same as [0] */
	if (os_ms_validate(&m) == 0) { printf("FAIL t3\n"); return 1; }
	mkfp(m.cosigner_fp[2], 30);
	printf("PASS t3 duplicate fp rejected\n");

	/* 4 record sigs to quorum */
	bool seen[OS_MS_MAX_COSIGNERS] = {false};
	uint8_t a[4], b[4]; mkfp(a, 10); mkfp(b, 20);
	if (os_ms_quorum(&m, seen)) { printf("FAIL t4 pre\n"); return 1; }
	os_ms_record_sig(&m, a, seen);
	if (os_ms_quorum(&m, seen)) { printf("FAIL t4 1 sig\n"); return 1; }
	os_ms_record_sig(&m, b, seen);
	if (!os_ms_quorum(&m, seen)) { printf("FAIL t4 2 sig\n"); return 1; }
	printf("PASS t4 quorum at M=2\n");

	/* 5 same signer twice doesn't double-count */
	bool seen2[OS_MS_MAX_COSIGNERS] = {false};
	os_ms_record_sig(&m, a, seen2);
	os_ms_record_sig(&m, a, seen2);
	if (os_ms_quorum(&m, seen2)) { printf("FAIL t5\n"); return 1; }
	printf("PASS t5 duplicate signer not double-counted\n");

	/* 6 unknown cosigner doesn't advance quorum */
	bool seen3[OS_MS_MAX_COSIGNERS] = {false};
	uint8_t stranger[4] = {99,99,99,99};
	os_ms_record_sig(&m, stranger, seen3);
	os_ms_record_sig(&m, a, seen3);
	if (os_ms_quorum(&m, seen3)) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 unknown cosigner ignored\n");

	printf("\nALL MULTISIG TESTS PASSED\n");
	return 0;
}
