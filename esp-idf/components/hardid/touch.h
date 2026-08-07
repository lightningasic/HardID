/*
 * HardID — CST816D capacitive touch driver (ESP32-S3-Touch-LCD-2)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Board: Waveshare ESP32-S3-Touch-LCD-2, CST816D over I2C.
 *   SDA = GPIO48, SCL = GPIO47, INT = GPIO46, I2C addr 0x15 (7-bit).
 *
 * The CST816 is interrupt-ready: it asserts INT on a touch, and only then
 * reliably answers I2C reads. We poll — enabling internal pull-ups and
 * reading the touch-point registers — for both a finger-down detection and
 * the (x,y) position, scaled to 0..LCD_H_RES / 0..LCD_V_RES.
 */

#ifndef HARDID_TOUCH_H
#define HARDID_TOUCH_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Init I2C bus + CST816D. Returns 0 on success, -1 on failure. */
int touch_init(void);

/* Probe: non-blocking. Sets *x,*y (screen pixels) only when touched.
 * Returns true while a finger is down. */
bool touch_get(int *x, int *y);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_TOUCH_H */