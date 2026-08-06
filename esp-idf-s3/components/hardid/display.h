/*
 * HardID — ST7789 display driver (ESP32-S3-Touch-LCD-2)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#ifndef HARDID_DISPLAY_H
#define HARDID_DISPLAY_H

#ifdef __cplusplus
extern "C" {
#endif

/* Init ST7789 (240x320). Returns 0 on success, -1 on failure. */
int lcd_init(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_DISPLAY_H */