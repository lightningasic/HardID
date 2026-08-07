/*
 * HardID — 5x7 bitmap font + minimal LCD text rendering (ESP32-S3)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Clean-room, dependency-free. 5x7 ASCII glyphs for the boot screen.
 * Each glyph is 5 bytes wide x 7 rows; bit set = foreground.
 */

#ifndef HARDID_DISPLAY_FONT_H
#define HARDID_DISPLAY_FONT_H

#include <stdint.h>
#include <stddef.h>

#define FONT_CHAR_W 5
#define FONT_CHAR_H 7

/* Return a pointer to 5 glyph bytes for ASCII 'c' (space = all zeros).
 * Non-printable/unknown map to a full block. */
const uint8_t *font7_glyph(char c);

#endif