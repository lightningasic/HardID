/*
 * HardID — ESP32-P4 board pin configuration
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Single place to wire the LCD / touch pins for the ESP32-P4 carrier board.
 * No screen is confirmed on the current P4 board yet — when hardware arrives,
 * adjust these values to the actual wiring (SCK/MOSI/CS/DC/RST/BL for the
 * ST7789 SPI LCD; SDA/SCL for the CST816D I2C touch). The rest of the UI
 * code reads only these macros, so a re-wire is a one-file change.
 */

#ifndef HARDID_BOARD_P4_H
#define HARDID_BOARD_P4_H

/* ---- ST7789 240x320 SPI LCD ---- */
#define PIN_LCD_SCK   39   /* PLACEHOLDER — set to the P4 board's LCD SCLK */
#define PIN_LCD_MOSI  38   /* PLACEHOLDER */
#define PIN_LCD_CS    45   /* PLACEHOLDER */
#define PIN_LCD_DC    42   /* PLACEHOLDER */
#define PIN_LCD_RST   (-1) /* -1 = software reset only (no hw reset line) */
#define PIN_LCD_BL     1   /* PLACEHOLDER */

/* ---- CST816D I2C touch ---- */
#define PIN_TOUCH_SDA 48   /* PLACEHOLDER */
#define PIN_TOUCH_SCL 47   /* PLACEHOLDER */

#endif /* HARDID_BOARD_P4_H */
