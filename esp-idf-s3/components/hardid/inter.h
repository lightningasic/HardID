/*
 * HardID — shared touch/input interaction primitives
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 0 (input): debounced poll-and-release over the CST816D, plus the
 * tiny hit-test and "hold until ack" helpers used by menu, keypad and
 * the screen flows. Kept in one place so the rest of the UI stays thin.
 */

#ifndef HARDID_INTER_H
#define HARDID_INTER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* True when (x,y) is inside the inclusive band [x0,y0]x[x1,y1). */
bool ui_pt_in(int x, int y, int x0, int y0, int x1, int y1);

/* Wait for a debounced touch press; returns its position. Blocking. */
bool ui_wait_press(int *px, int *py);

/* Wait for the finger to lift. Blocking; returns release position. */
void ui_wait_release(int *rx, int *ry);

/* Show "tap to return" and hold until the user taps. Blocking. */
void ui_wait_ack(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_INTER_H */