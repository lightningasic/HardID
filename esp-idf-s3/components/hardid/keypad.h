/*
 * HardID — on-screen alphanumeric keypad + confirmation dialogs
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 1 (widgets): a full touch keypad with numeric and alphabetic
 * pages (toggle), a PIN set/enter routine and modal confirm dialogs.
 * No knowledge of the SE or device flows — pure input widgets.
 */

#ifndef HARDID_KEYPAD_H
#define HARDID_KEYPAD_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Capture a string via the keypad. Returns 0 on OK, -1 on cancel/timeout.
 * If numeric_only, non-digit keys are ignored. */
int kp_capture(const char *title, char *out, int max, int numeric_only);

/* Confirmation dialog (clears the screen, shows msg). True if "Confirm". */
bool ui_confirm(const char *msg);

/* Confirmation drawn over existing content (no screen clear). True if
 * "Confirm". */
bool ui_confirm_overlay(void);

/* Prompt & confirm a new PIN (both entries must match, >= OS_PIN_MIN_LEN).
 * On success stores ASCII PIN in out (<=OS_PIN_MAX_LEN) and returns its
 * length; -1 on failure. */
int ui_set_pin(char *out, int out_max);

/* Prompt for the PIN once for unlock. Stores ASCII PIN in out, returns its
 * length, or -1 on failure. */
int ui_enter_pin(char *out, int out_max);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_KEYPAD_H */