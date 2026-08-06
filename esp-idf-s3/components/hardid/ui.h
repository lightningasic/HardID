/*
 * HardID — on-screen user interface (main menu + event loop)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 3 (application): the home menu and the touch event loop routing
 * taps to the three screen flows. PIN/keypad primitives live in keypad.h.
 */

#ifndef HARDID_UI_H
#define HARDID_UI_H

#ifdef __cplusplus
extern "C" {
#endif

/* Run the three-function menu. Calls se to init/sign/wipe.
 * Never returns (main loop). */
void ui_run(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_UI_H */