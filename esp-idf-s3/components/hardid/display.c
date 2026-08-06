/*
 * HardID — ST7789 240x320 display driver for ESP32-S3-Touch-LCD-2
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Waveshare ESP32-S3-Touch-LCD-2 LCD wiring (verified from CircuitPython
 * board definition / Waveshare docs):
 *   SCK  = GPIO39
 *   MOSI = GPIO38
 *   CS   = GPIO45
 *   DC   = GPIO42
 *   RST  = GPIO0   (shared with BOOT button — do NOT pull low after boot)
 *   BL   = GPIO1   (backlight, active high)
 *   MISO = GPIO40  (unused)
 *
 * Uses the ESP-IDF esp_lcd component (esp_lcd_panel_io + st7789 panel ops).
 * Implements the boot.h board display hooks plus a minimal line-based text
 * renderer driven by font7.h.
 *
 * SECURITY NOTE: This board routes LCD reset to GPIO0 (the BOOT strapping
 * pin). Asserting a hardware reset here would reboot the MCU into the ROM
 * bootloader, so we use ST7789's software reset command (MIPI DCS 0x01)
 * instead and keep GPIO0 high after boot.
 */

#include <string.h>
#include <stdio.h>

#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_st7789.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_log.h"

#include "boot.h"
#include "font7.h"

#define LCD_H_RES 240
#define LCD_V_RES 320

/* board pins */
#define PIN_LCD_SCK  39
#define PIN_LCD_MOSI 38
#define PIN_LCD_CS   45
#define PIN_LCD_DC   42
#define PIN_LCD_RST  0   /* shared with BOOT; software reset only */
#define PIN_LCD_BL   1

#define SPI_HOST_MAX   SPI2_HOST
#define LCD_SPI_FREQ  (40 * 1000 * 1000)

static const char *TAG = "hardid.lcd";

static esp_lcd_panel_io_handle_t s_io = NULL;
static esp_lcd_panel_handle_t     s_panel = NULL;

static void lcd_fill_panel(uint16_t color);
void lcd_fill(uint16_t color);

int lcd_init(void)
{
	esp_err_t rc;

	/* backlight: on, high */
	gpio_config_t bl = {
		.pin_bit_mask = 1ULL << PIN_LCD_BL,
		.mode = GPIO_MODE_OUTPUT,
		.pull_up_en = GPIO_PULLUP_DISABLE,
		.pull_down_en = GPIO_PULLDOWN_DISABLE,
		.intr_type = GPIO_INTR_DISABLE,
	};
	rc = gpio_config(&bl);
	if (rc != ESP_OK) return -1;
	gpio_set_level(PIN_LCD_BL, 1);

	/* SPI bus: MOSI+SCLK (MISO unused; DC/CS as GPIO) */
	spi_bus_config_t bus = {
		.sclk_io_num = PIN_LCD_SCK,
		.mosi_io_num = PIN_LCD_MOSI,
		.miso_io_num = -1,
		.quadwp_io_num = -1,
		.quadhd_io_num = -1,
		.max_transfer_sz = LCD_H_RES * 2,
	};
	rc = spi_bus_initialize(SPI2_HOST, &bus, SPI_DMA_CH_AUTO);
	if (rc != ESP_OK) return -1;

	esp_lcd_panel_io_spi_config_t io_cfg = {
		.dc_gpio_num = PIN_LCD_DC,
		.cs_gpio_num = PIN_LCD_CS,
		.pclk_hz = LCD_SPI_FREQ,
		.lcd_cmd_bits = 8,
		.lcd_param_bits = 8,
		.spi_mode = 0,
		.trans_queue_depth = 10,
		.on_color_trans_done = NULL,
		.user_ctx = NULL,
	};
	rc = esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)SPI2_HOST,
	                              &io_cfg, &s_io);
	if (rc != ESP_OK) return -1;

	esp_lcd_panel_dev_config_t panel_cfg = {
		.reset_gpio_num = -1,   /* no hw reset: RST shares BOOT/GPIO0 */
		.color_space = ESP_LCD_COLOR_SPACE_RGB,
		.bits_per_pixel = 16,
	};
	rc = esp_lcd_new_panel_st7789(s_io, &panel_cfg, &s_panel);
	if (rc != ESP_OK) return -1;

	/* software reset + init (no GPIO0 assertion) */
	rc = esp_lcd_panel_reset(s_panel);
	if (rc != ESP_OK) return -1;
	rc = esp_lcd_panel_init(s_panel);
	if (rc != ESP_OK) return -1;

	/* 16bpp -> panel in 16bit color mode */
	esp_lcd_panel_io_tx_param(s_io, 0x3A, (uint8_t[]){ 0x55 }, 1);
	/* MADCTL: 240 (portrait) by default; no rotation for this boot screen */
	esp_lcd_panel_invert_color(s_panel, true);
	esp_lcd_panel_disp_on_off(s_panel, true);

	lcd_fill(0x0000); /* black */
	ESP_LOGI(TAG, "ST7789 init OK (%dx%d)", LCD_H_RES, LCD_V_RES);
	return 0;
}

static void lcd_fill_panel(uint16_t color)
{
	uint16_t line[LCD_H_RES];
	for (int i = 0; i < LCD_H_RES; i++)
		line[i] = color;
	for (int y = 0; y < LCD_V_RES; y++)
		esp_lcd_panel_draw_bitmap(s_panel, 0, y, LCD_H_RES, y + 1, line);
}

void lcd_fill(uint16_t color) { lcd_fill_panel(color); }

/* Render an ASCII string at (x,y) in fg on bg. Glyphs are column-major:
 * font7_glyph() returns 5 bytes, byte c = column c, bit r = row r (bit0=top). */
void lcd_line(int x, int y, const char *s, uint16_t fg, uint16_t bg)
{
	if (!s) return;
	size_t len = strlen(s);
	for (size_t ci = 0; ci < len; ci++) {
		const uint8_t *gl = font7_glyph(s[ci]);
		for (int col = 0; col < FONT_CHAR_W; col++) {
			int xx = x + (int)ci * (FONT_CHAR_W + 1) + col;
			if (xx < 0 || xx >= LCD_H_RES) continue;
			uint16_t strip[FONT_CHAR_H];
			uint8_t bits = gl[col];
			for (int row = 0; row < FONT_CHAR_H; row++)
				strip[row] = (bits & (1u << row)) ? fg : bg;
			int y0 = (y < 0) ? 0 : y;
			int y1 = y + FONT_CHAR_H;
			if (y1 > LCD_V_RES) y1 = LCD_V_RES;
			if (y0 < y1)
				esp_lcd_panel_draw_bitmap(s_panel, xx, y0, xx + 1, y1, &strip[y0 - y]);
		}
	}
}

#define LINE_H (FONT_CHAR_H + 2)

int lcd_text_wrap(int x, int y, const char *s, uint16_t fg, uint16_t bg)
{
	if (!s) return y;
	int cur = y;
	/* max chars that fit on a line of width LCD_H_RES */
	int maxch = (LCD_H_RES - x) / (FONT_CHAR_W + 1);
	if (maxch < 1) return y;
	/* fill a buffer one line at a time, breaking at spaces when possible */
	char line[LCD_H_RES / (FONT_CHAR_W + 1) + 2];
	const char *p = s;
	while (*p) {
		int n = 0;
		while (n < maxch && p[n] && p[n] != '\n') {
			line[n] = p[n];
			n++;
		}
		/* if we stopped early due to a space, absorb it */
		if (n == maxch) {
			/* find last space to break more cleanly */
			int brk = n;
			for (int i = n - 1; i > 0; i--) {
				if (line[i] == ' ') { brk = i; break; }
			}
			if (brk > 0 && brk < maxch) {
				line[brk] = '\0';
				p += brk + 1;
			} else {
				line[n] = '\0';
				p += n;
			}
		} else {
			line[n] = '\0';
			p += n;
			if (*p == '\n') p++;
		}
		lcd_line(x, cur, line, fg, bg);
		cur += LINE_H;
		if (cur + FONT_CHAR_H > LCD_V_RES) break;
	}
	return cur;
}

void os_board_display_home(void)
{
	if (!s_panel) { lcd_init(); }
	lcd_fill(0x0000);
	/* status bar */
	lcd_line(2, 2, "HardID", 0xE73C, 0x0000);
	lcd_line(2, 14, "Wallet v0.1 - mock SE", 0xAD75, 0x0000);
	lcd_line(2, 28, "ready", 0x3F00, 0x0000);
}

void os_board_display_error(const char *line1, const char *line2)
{
	if (!s_panel) { lcd_init(); }
	lcd_fill(0xF800); /* red */
	lcd_line(2, 2, "ERROR", 0xFFFF, 0xF800);
	if (line1) lcd_line(2, 16, line1, 0xFFFF, 0xF800);
	if (line2) lcd_line(2, 30, line2, 0xFFFF, 0xF800);
}