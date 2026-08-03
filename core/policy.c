/*
 * OpenShield Hardware Wallet — auto-sign policy (SignPolicy)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
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

	/* pending change not yet active: policy stays at old (tighter) values */
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
	/* store the pending limits in the live fields but gate activation */
	p->per_tx_limit = new_per_tx;
	p->window_limit = new_window_limit;
	p->activate_after = now + OS_POLICY_COOLDOWN_S;
	os_policy_persist(p);
}

bool os_policy_in_cooldown(const os_policy *p, uint32_t now)
{
	return p->activate_after != 0 && now < p->activate_after;
}
