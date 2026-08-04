/*
 * HardID Hardware Wallet — auto-sign policy (SignPolicy)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Auto-sign under user-set limits (per-tx + rolling time window). Policy
 * changes take effect only after a 24h cool-down to prevent a transient
 * host compromise from instantly raising limits. Window counters persist
 * in the SE across power loss; exceeding limits falls back to manual
 * Clear Sign confirmation.
 */

#ifndef HARDID_POLICY_H
#define HARDID_POLICY_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_POLICY_COOLDOWN_S (24u * 3600u)

typedef struct {
	uint64_t per_tx_limit;    /* ACTIVE max amount per single tx */
	uint64_t window_limit;    /* ACTIVE max total per window */
	uint32_t window_seconds;  /* rolling window length */
	uint64_t window_spent;    /* spent in current window (persisted) */
	uint32_t window_start;    /* epoch of current window start (persisted) */
	uint32_t activate_after;  /* pending-change activates at this epoch; 0=none */
	/* Pending limits (take effect only after the cool-down). Kept separate
	 * from the ACTIVE limits so authorize() enforces the OLD limits until
	 * activate_after passes — a transient host compromise cannot raise
	 * limits instantly. */
	uint64_t pending_per_tx;
	uint64_t pending_window_limit;
} os_policy;

/* ---- Time/persistence hooks (implement over SE/RTC) ---- */
uint32_t os_policy_now(void);
void os_policy_persist(const os_policy *p);

/* ---- Logic (portable) ---- */

/* Advance the rolling window if expired (mutates p, persists). */
void os_policy_roll_window(os_policy *p, uint32_t now);

/* Can this amount be auto-signed right now? Rolls the window first.
 * Returns true and consumes quota (persists) if within limits. */
bool os_policy_authorize(os_policy *p, uint64_t amount);

/* Schedule a policy change to (new_per_tx, new_window_limit).
 * Takes effect only after the cool-down. Writes pending values into p. */
void os_policy_schedule_change(os_policy *p, uint32_t now,
                               uint64_t new_per_tx, uint64_t new_window_limit);

/* Returns true while a scheduled change is still in cool-down. */
bool os_policy_in_cooldown(const os_policy *p, uint32_t now);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_POLICY_H */
