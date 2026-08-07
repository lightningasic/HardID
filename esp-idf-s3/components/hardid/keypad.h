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
 * If numeric_only, non-digit keys are ignored. If mask, the entered text is
 * echoed as '*' (used for PINs); otherwise it is shown in plain text (e.g.
 * an on-screen recovery phrase the user must verify). */
int kp_capture(const char *title, char *out, int max, int numeric_only,
               int mask);

/* Swipe-to-select input for alphabetic entry (recovery phrase): the finger
 * slides over the letter grid, the hovered cell is highlighted and its
 * character is shown enlarged in a floating preview box; releasing commits
 * it. Returns 0 on OK, -1 on cancel/timeout. */
int kp_capture_alpha(const char *title, char *out, int max);

/* Word-by-word mnemonic recovery entry. The user swipes the letters of a
 * word's unique prefix (first 4 letters, or the whole word when shorter and
 * terminal); as soon as the prefix is unambiguous the full word is resolved
 * from the BIP39 list, inserted into the phrase and the keypad advances.
 * Returns 0 with the space-separated lowercase phrase in out on OK, -1 on
 * cancel/timeout. */
int kp_capture_phrase(const char *title, char *out, int max);

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