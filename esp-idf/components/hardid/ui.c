/*
 * HardID — on-screen user interface (main menu + event loop)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 3 (application): the home menu and the touch event loop that
 * routes taps to the five screen flows. The screen is small (240x320),
 * so the menu shows ONE item at a time in a large typeface and the user
 * steps through the five actions with on-screen left/right arrow keys.
 * Input primitives live in inter.c, the keypad/confirm in keypad.c, and
 * the flows in screen.c.
 */

#include <string.h>

#include "display.h"
#include "inter.h"
#include "keypad.h"
#include "pin.h"
#include "se_driver.h"
#include "screen.h"
#include "secure_zero.h"
#include "ui.h"

#define MENU_COUNT 6

static const char *const s_items[MENU_COUNT] = {
	"INITIALIZE", "SIGN", "RECOVER", "HOST LINK", "FACTORY RESET",
	"ABOUT",
};

static int s_sel = 0;

#define ARROW_Y0  230
#define ARROW_Y1  290
#define ARROW_X0  15
#define ARROW_X1  75
#define RARROW_X0 165
#define RARROW_X1 225

/* Draw `s` centered horizontally with 8x16 glyphs at 2x scale (16x32px
 * per char). Used for the single visible menu item. */
static void menu_draw_item(const char *s, int y)
{
	int len = (int)strlen(s);
	int scale = 2;
	int adv = F8_W * scale + 2;
	int tw = len * adv - 2;
	int x = (240 - tw) / 2;
	if (x < 0) x = 0;
	for (int i = 0; i < len; i++)
		lcd_gl8x16(x + i * adv, y, s[i], C_FG, C_BG, scale);
}

static int isqrt(int v)
{
	int r = 0;
	while ((r + 1) * (r + 1) <= v) r++;
	return r;
}

/* Filled rounded-corner rectangle (radius r), one display row per blit. */
static void draw_round_rect(int x0, int y0, int x1, int y1, int r,
                            uint16_t color)
{
	if (r < 1) { lcd_rect(x0, y0, x1, y1, color); return; }
	for (int y = y0; y < y1; y++) {
		int d;
		if (y < y0 + r)
			d = (y0 + r - 1) - y;
		else if (y >= y1 - r)
			d = y - (y1 - r);
		else
			d = -1;
		int inset = (d >= 0) ? r - isqrt(r * r - d * d) : 0;
		lcd_rect(x0 + inset, y, x1 - inset, y + 1, color);
	}
}

/* Left/right arrow key: a small solid triangle centered on a rounded
 * button band. Rendered geometrically because the embedded 8x16 font has
 * no '<'/'>' glyphs. dir<0 = point left, dir>=0 = point right. */
static void draw_arrow(int x0, int y0, int x1, int y1, int dir)
{
	draw_round_rect(x0, y0, x1, y1, 8, C_BTN);
	int xc = (x0 + x1) / 2, yc = (y0 + y1) / 2;
	int hw = (x1 - x0) / 5;   /* half width of the arrow head */
	int hh = (y1 - y0) / 4;   /* half height of the arrow head */
	for (int dy = -hh; dy <= hh; dy++) {
		int t = (dy < 0 ? -dy : dy);
		int w = 2 * hw * (hh - t) / hh;
		if (w <= 0) continue;
		int y = yc + dy;
		if (dir < 0)
			lcd_rect(xc + hw - w, y, xc + hw, y + 1, C_FG);
		else
			lcd_rect(xc - hw, y, xc - hw + w, y + 1, C_FG);
	}
}

static void menu_draw(void)
{
	lcd_fill(C_BG);
	lcd_line(2, 8, "HardID", C_LBL, C_BG);
	lcd_line(2, 22, "tap to open", C_DIM, C_BG);

	menu_draw_item(s_items[s_sel], 140);

	draw_arrow(ARROW_X0, ARROW_Y0, ARROW_X1, ARROW_Y1, -1);
	draw_arrow(RARROW_X0, ARROW_Y0, RARROW_X1, ARROW_Y1, 1);
}

static void menu_run_sel(void)
{
	switch (s_sel) {
	case 0: screen_run_initialize();    break;
	case 1: screen_run_sign();          break;
	case 2: screen_run_recover();       break;
	case 3: screen_run_link_host();     break;
	case 4: screen_run_factory_reset(); break;
	case 5: screen_run_about();         break;
	}
}

/* First-boot PIN gate. If the SE carries no PIN yet (fresh device or after
 * a wipe), force the user to set one before any menu action is reachable.
 * The PIN protects the device from the first power-on, independent of the
 * seed, and persists across factory resets. */
static void boot_pin_gate(void)
{
	const se_driver_t *se = se_active();
	bool pin_set = false;
	if (se->is_pin_set && se->is_pin_set(&pin_set) == SE_OK && pin_set)
		return;
	char pin[OS_PIN_MAX_LEN + 1];
	int len = ui_set_pin(pin, (int)sizeof(pin));
	if (len >= 0) {
		se->set_pin((const uint8_t *)pin, (size_t)len);
		os_secure_bzero(pin, sizeof(pin));
	}
}

void ui_run(void)
{
	boot_pin_gate();
	for (;;) {
		menu_draw();
		int px, py;
		if (!ui_wait_press(&px, &py))
			continue;
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;
		if (ui_pt_in(px, py, ARROW_X0, ARROW_Y0, ARROW_X1, ARROW_Y1)) {
			s_sel = (s_sel + MENU_COUNT - 1) % MENU_COUNT;
		} else if (ui_pt_in(px, py, RARROW_X0, ARROW_Y0, RARROW_X1, ARROW_Y1)) {
			s_sel = (s_sel + 1) % MENU_COUNT;
		} else {
			menu_run_sel();
		}
	}
}
