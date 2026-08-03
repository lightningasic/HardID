/*
 * OpenShield Hardware Wallet — PIN access control
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "pin.h"

uint32_t os_pin_backoff_seconds(uint32_t fail_count)
{
	uint32_t wait;
	if (fail_count == 0)
		return 0;
	/* base * 2^(fail_count-1), capped; avoid UB on large shifts */
	if (fail_count >= 32)
		return OS_PIN_BACKOFF_MAX_S;
	wait = OS_PIN_BACKOFF_BASE_S << (fail_count - 1);
	if (wait > OS_PIN_BACKOFF_MAX_S || wait == 0)
		wait = OS_PIN_BACKOFF_MAX_S;
	return wait;
}

uint32_t os_pin_remaining(const os_pin_state *st, uint32_t now)
{
	if (st->lock_until == 0 || now >= st->lock_until)
		return 0;
	return st->lock_until - now;
}

uint32_t os_pin_attempt(const uint8_t *pin, size_t len, bool *is_duress)
{
	os_pin_state st;
	uint32_t now = os_pin_now();
	uint32_t wait;
	bool duress = false;

	os_pin_load_state(&st);

	/* still in backoff: report remaining, do not even verify */
	wait = os_pin_remaining(&st, now);
	if (wait > 0)
		return wait;

	/* backoff expired (or none): clear any stale lock */
	if (st.lock_until != 0) {
		st.lock_until = 0;
		os_pin_save_state(&st);
	}

	if (os_pin_hw_verify(pin, len, &duress)) {
		if (st.fail_count != 0) {
			st.fail_count = 0;
			os_pin_save_state(&st);
		}
		if (is_duress)
			*is_duress = duress;
		return 0;
	}

	/* failure: increment and arm next backoff, persist immediately */
	st.fail_count++;
	/* failure: increment and arm next backoff, persist immediately.
	 * Saturate lock_until to avoid uint32 wraparound bypassing backoff. */
	{
		uint32_t backoff = os_pin_backoff_seconds(st.fail_count);
		uint32_t max_future = 0xFFFFFFFFu - now;
		st.lock_until = (backoff > max_future) ? 0xFFFFFFFFu
		                                      : now + backoff;
	}
	os_pin_save_state(&st);
	return st.lock_until - now;
}
