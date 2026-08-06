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

/* Clear the whole panel to a 16-bit RGB565 color. */
void lcd_fill(uint16_t color);

/* Draw a single line of text at (x,y) in fg on bg. Clips to panel. */
void lcd_line(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* Draw text with simple word-wrap within the panel width, starting at
 * (x,y). Returns the y just below the last drawn line. */
int lcd_text_wrap(int x, int y, const char *s, uint16_t fg, uint16_t bg);

/* Fill a rectangle with a solid 16-bit RGB565 color. Clips to panel. */
void lcd_rect(int x0, int y0, int x1, int y1, uint16_t color);

/* Draw a text label centered horizontally on a filled rect, clipped to it. */
void lcd_rect_text(int x0, int y0, int x1, int y1, const char *s,
                   uint16_t fg, uint16_t bg);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_DISPLAY_H */