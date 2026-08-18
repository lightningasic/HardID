/*
 * HardID Hardware Wallet — auto-sign policy (SignPolicy)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "policy.h"

void os_policy_roll_window(os_policy *p, uint32_t now)
{
	if (p->window_seconds == 0)
		return;
	if (now - p->window_start >= p->window_seconds) {
		p->window_start = now;
		p->window_spent = 0;
		os_policy_persist(p);
	}
}

bool os_policy_authorize(os_policy *p, uint64_t amount)
{
	uint32_t now = os_policy_now();

	/* Activate a pending change whose cool-down has elapsed. */
	if (p->activate_after != 0 && now >= p->activate_after) {
		p->per_tx_limit = p->pending_per_tx;
		p->window_limit = p->pending_window_limit;
		p->activate_after = 0;
		os_policy_persist(p);
	}

	os_policy_roll_window(p, now);

	if (amount > p->per_tx_limit)
		return false;
	/* overflow-safe window check. Guard spent<=limit so a corrupted or
	 * out-of-range persisted state fails closed instead of wrapping. */
	if (p->window_spent > p->window_limit)
		return false;
	if (amount > p->window_limit - p->window_spent)
		return false;

	p->window_spent += amount;
	os_policy_persist(p);
	return true;
}

void os_policy_schedule_change(os_policy *p, uint32_t now,
                               uint64_t new_per_tx, uint64_t new_window_limit)
{
	/* Store into PENDING fields; ACTIVE limits stay unchanged until the
	 * cool-down elapses. Never touches per_tx_limit/window_limit here. */
	p->pending_per_tx = new_per_tx;
	p->pending_window_limit = new_window_limit;
	/* saturate against uint32 now-wrap (mirrors pin.c lock_until): a
	 * wrapped activate_after would land in the past and let the next
	 * authorize() activate the new limits immediately */
	p->activate_after =
		(OS_POLICY_COOLDOWN_S > 0xFFFFFFFFu - now) ? 0xFFFFFFFFu
		                                          : now + OS_POLICY_COOLDOWN_S;
	os_policy_persist(p);
}

bool os_policy_in_cooldown(const os_policy *p, uint32_t now)
{
	return p->activate_after != 0 && now < p->activate_after;
}
