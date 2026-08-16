/*
 * HardID — ST7789 display driver (ESP32-S3-Touch-LCD-2)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#ifndef HARDID_DISPLAY_H
#define HARDID_DISPLAY_H

#include <stdint.h>

#include "font8x16.h"

#define C_BG   0x0000
#define C_FG   0xFFFF
#define C_LBL  0xE73C
#define C_DIM  0x8410
#define C_BTN  0x039E  /* brand blue: the logo bolt (0,113,242) */
#define C_OK   0x07E0
#define C_ERR  0xF800
#define C_WARN 0xFD20

/* Panel resolution (ST7789 portrait). */
#define LCD_H_RES 240
#define LCD_V_RES 320

#ifdef __cplusplus
extern "C" {
#endif

/* Init ST7789 (240x320). Returns 0 on success, -1 on failure. */
int lcd_init(void);

/* Clear the whole panel to a 16-bit RGB565 color. */
void lcd_fill(uint16_t color);

/* Draw a single line of text at (x,y) in fg on bg. Clips to panel. */
void lcd_line(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* Draw a line of text at 2x scale (each glyph pixel becomes 2x2). Clips to
 * panel. Used for entries the user must read (e.g. recovery phrase). */
void lcd_line_big(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* Draw a line of text at integer `scale` (each glyph pixel becomes a
 * scale x scale block). Clips to the panel. Serves the floating swipe
 * preview. */
void lcd_line_scaled(int x, int y, const char *s, uint16_t fg, uint16_t bg,
                     int scale);

/* Draw a single 8x16 glyph (high-res, row-major) at integer `scale`
 * centered/top-left at (x,y) in fg on bg. Clips to the panel. Serves the
 * floating swipe preview, which upscales the 5x7 font with visible steps. */
void lcd_gl8x16(int x, int y, char ch, uint16_t fg, uint16_t bg, int scale);

/* Draw one 16x16 CJK glyph (16 uint16_t rows, bit 15 = leftmost) at
 * integer `scale`. Clips to the panel. */
void lcd_cjk16(int x, int y, const uint16_t *glyph16, uint16_t fg,
               uint16_t bg, int scale);

/* Draw a UTF-8 string: ASCII via the 8x16 font, non-ASCII via the embedded
 * CJK subset font, at integer `scale`. Returns the pixel width drawn. */
int lcd_utf8_str(int x, int y, const char *s, uint16_t fg, uint16_t bg,
                 int scale);

/* Pixel width the UTF-8 string would occupy at `scale` (without drawing). */
int lcd_utf8_width(const char *s, int scale);

/* Draw text with simple word-wrap within the panel width, starting at
 * (x,y). Returns the y just below the last drawn line. */
int lcd_text_wrap(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* UTF-8 word-wrap: breaks on spaces when possible, on a CJK-capable width
 * otherwise, and renders each line at 1x scale (16px lines, +2 spacing).
 * Returns the y just past the last rendered line. */
int lcd_text_wrap_utf8(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* Fill a rectangle with a solid 16-bit RGB565 color. Clips to panel. */
void lcd_rect(int x0, int y0, int x1, int y1, uint16_t color);

/* Draw a text label centered horizontally on a filled rect, clipped to it. */
void lcd_rect_text(int x0, int y0, int x1, int y1, const char *s,
                   uint16_t fg, uint16_t bg);

/* Same as lcd_rect_text but renders UTF-8 (ASCII + CJK) at 1x scale, for
 * localized button labels. */
void lcd_rect_text_utf8(int x0, int y0, int x1, int y1, const char *s,
                        uint16_t fg, uint16_t bg);

/* Draw a w x h RGB565 bitmap (row-major) with (x,y) as its top-left corner.
 * Clips to the panel. Used by the boot logo. */
void lcd_bitmap(int x, int y, int w, int h, const uint16_t *rgb565);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_DISPLAY_H */