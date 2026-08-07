/*
 * HardID — 8x16 bitmap font for the floating swipe preview
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Higher-resolution 8x16 glyphs (Spleen-derived, BSD-2-Clause) so the
 * enlarged recovery-phrase preview reads cleanly without the steps/jaggies
 * of upscaling the 5x7 UI font. Row-major: byte = row, bit 7 = leftmost.
 */

#ifndef HARDID_DISPLAY_FONT8X16_H
#define HARDID_DISPLAY_FONT8X16_H

#include <stdint.h>
#include <stddef.h>

#define F8_W 8
#define F8_H 16

/* Return a pointer to 16 glyph bytes for ASCII 'c'. Row-major; bit 7 of
 * byte r is column 0 (leftmost). Unknown chars map to an empty glyph. */
const uint8_t *font8x16_glyph(char c);

#endif