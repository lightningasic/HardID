/*
 * OpenShield Hardware Wallet — PIN access control
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * DESIGN RED LINE: NO SELF-DESTRUCT. A hardware wallet may hold the only
 * copy of a private key; any wipe-on-fail mechanism can permanently destroy
 * the user's assets. Defense is pure time cost: exponential backoff with no
 * attempt cap. A 6-digit PIN (10^6 space) under 2^n-second backoff takes
 * decades to brute-force — equivalent protection, zero loss risk.
 *
 * All mutable state (fail_count, lock_until, PIN hash) lives in the secure
 * element; this module holds the policy logic and is storage-agnostic via
 * the hooks below. State must persist across power loss.
 */

#ifndef OPENSHIELD_PIN_H
#define OPENSHIELD_PIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Backoff: wait = base * 2^(fail_count-1) seconds, capped. */
#define OS_PIN_BACKOFF_BASE_S   1u
#define OS_PIN_BACKOFF_MAX_S    (24u * 3600u)   /* cap at 24 hours */
#define OS_PIN_MAX_LEN          16
#define OS_PIN_MIN_LEN          4

typedef struct {
	uint32_t fail_count;    /* consecutive failures (persisted in SE) */
	uint32_t lock_until;    /* epoch seconds; 0 = unlocked (persisted) */
} os_pin_state;

/* ---- Storage hooks (implement over SE) — must persist across power loss ---- */
void os_pin_load_state(os_pin_state *st);
void os_pin_save_state(const os_pin_state *st);
/* Constant-time PIN verification inside the SE. Returns true if match.
 * If a duress PIN is configured and matches, *is_duress (if non-NULL)
 * is set true and the function returns true (caller shows decoy view). */
bool os_pin_hw_verify(const uint8_t *pin, size_t len, bool *is_duress);
/* Monotonic-ish time in seconds (RTC or uptime counter in SE). */
uint32_t os_pin_now(void);

/* ---- Policy logic (portable, unit-testable) ---- */

/* Backoff wait in seconds for the NEXT failure after fail_count failures. */
uint32_t os_pin_backoff_seconds(uint32_t fail_count);

/* Attempt unlock.
 *  - If still in backoff, returns remaining wait seconds (>0), no verify.
 *  - Otherwise verifies: on success resets fail_count and returns 0;
 *    on failure increments fail_count, arms next backoff, returns new wait.
 * *is_duress (optional) is set when the duress PIN matched. */
uint32_t os_pin_attempt(const uint8_t *pin, size_t len, bool *is_duress);

/* Remaining lock seconds at time `now` for state `st` (0 if unlocked). */
uint32_t os_pin_remaining(const os_pin_state *st, uint32_t now);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_PIN_H */
