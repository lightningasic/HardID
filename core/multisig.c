/*
 * HardID Hardware Wallet — multisig (M-of-N) configuration
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "multisig.h"
#include <string.h>

int os_ms_validate(const os_multisig *m)
{
	if (m->threshold_m < 1 || m->threshold_m > m->total_n)
		return -1;
	if (m->total_n < 1 || m->total_n > OS_MS_MAX_COSIGNERS)
		return -1;
	/* fingerprints must be unique */
	for (uint8_t i = 0; i < m->total_n; i++)
		for (uint8_t j = i + 1; j < m->total_n; j++)
			if (memcmp(m->cosigner_fp[i], m->cosigner_fp[j], 4) == 0)
				return -1;
	if (m->self_index != 0xFF && m->self_index >= m->total_n)
		return -1;
	return 0;
}

uint8_t os_ms_find(const os_multisig *m, const uint8_t fp[4])
{
	for (uint8_t i = 0; i < m->total_n; i++)
		if (memcmp(m->cosigner_fp[i], fp, 4) == 0)
			return i;
	return 0xFF;
}

uint8_t os_ms_record_sig(const os_multisig *m, const uint8_t fp[4],
                         bool seen[OS_MS_MAX_COSIGNERS])
{
	uint8_t idx = os_ms_find(m, fp);
	if (idx == 0xFF)
		return 0xFF;              /* unknown cosigner — caller must notice */
	seen[idx] = true;
	return idx;
}

bool os_ms_quorum(const os_multisig *m, const bool seen[OS_MS_MAX_COSIGNERS])
{
	uint8_t count = 0;
	for (uint8_t i = 0; i < m->total_n; i++)
		if (seen[i])
			count++;
	return count >= m->threshold_m;
}
