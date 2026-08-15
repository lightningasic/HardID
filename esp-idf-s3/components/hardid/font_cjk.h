/*
 * HardID — embedded CJK bitmap font subset
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0 (glyph data: GNU Unifont, GPL-2.0-or-later
 * with the Font-embedding exception)
 *
 * A small 16x16 subset of GNU Unifont covering exactly the glyphs used by
 * the multi-language menu (English / Chinese / Japanese / Korean), so the
 * menu labels render without embedding the entire CJK font.
 */

#ifndef HARDID_DISPLAY_FONT_CJK_H
#define HARDID_DISPLAY_FONT_CJK_H

#include <stdint.h>

/* Return 16 uint16_t rows (one per scanline, bit 15 = leftmost pixel) for
 * a 16x16 CJK glyph, or NULL if the codepoint is not in the subset. */
const uint16_t *font_cjk_glyph(uint32_t cp);

#endif /* HARDID_DISPLAY_FONT_CJK_H */
