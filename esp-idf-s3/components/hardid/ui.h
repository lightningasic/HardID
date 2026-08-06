/*
 * HardID — on-screen user interface (menu + alphanumeric keypad)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Three-function Trezor-style framework driven entirely by touch:
 *   1. Initialize   — generate seed, show recovery phrase, set PIN
 *   2. Sign         — unlock w/ PIN, sign a fixed digest, show sig
 *   3. Factory reset— confirm, wipe SE state
 *
 * UI primitives: a menu of tappable buttons, a confirmation dialog,
 * and a full on-screen keypad with numeric + alphabetic modes so the
 * device stays usable with zero physical buttons.
 */

#ifndef HARDID_UI_H
#define HARDID_UI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Set the PIN in UI. Prompts "New PIN" twice with the keypad; both entries
 * must match and be >= OS_PIN_MIN_LEN. On success stores the ASCII PIN in
 * out (<=OS_PIN_MAX_LEN) and returns its length; returns -1 on failure. */
int ui_set_pin(char *out, int out_max);

/* Prompt for the PIN via the keypad; stores ASCII PIN in out, returns its
 * length, or -1 on failure. */
int ui_enter_pin(char *out, int out_max);

/* Run the three-function menu. Calls se to init/sign/wipe.
 * Never returns (main loop). */
void ui_run(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_UI_H */