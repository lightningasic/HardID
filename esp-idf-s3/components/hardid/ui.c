/*
 * HardID — on-screen user interface (main menu + event loop)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 3 (application): the home menu and the touch event loop that
 * routes taps to the three screen flows. Input primitives live in
 * inter.c, the keypad/confirm in keypad.c, and the flows in screen.c.
 */

#include "display.h"
#include "inter.h"
#include "screen.h"
#include "ui.h"

static void menu_draw(void)
{
	lcd_fill(C_BG);
	lcd_line(2, 2, "HardID", C_LBL, C_BG);
	lcd_line(2, 14, "tap an action", C_DIM, C_BG);
	lcd_rect_text(15, 38,  225,  88, "1  Initialize", C_FG, C_BTN);
	lcd_rect_text(15, 96,  225, 146, "2  Sign", C_FG, C_BTN);
	lcd_rect_text(15, 154, 225, 204, "3  Recover", C_FG, C_BTN);
	lcd_rect_text(15, 212, 225, 262, "4  Factory reset", C_FG, C_BTN);
}

static bool menu_handle_press(int px, int py)
{
	if (ui_pt_in(px, py, 15, 38,  225, 88))  { screen_run_initialize();    return true; }
	if (ui_pt_in(px, py, 15, 96,  225, 146)) { screen_run_sign();          return true; }
	if (ui_pt_in(px, py, 15, 154, 225, 204)) { screen_run_recover();       return true; }
	if (ui_pt_in(px, py, 15, 212, 225, 262)) { screen_run_factory_reset(); return true; }
	return false;
}

void ui_run(void)
{
	menu_draw();
	for (;;) {
		int px, py;
		if (!ui_wait_press(&px, &py))
			continue;
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		    (rx == px && ry == py))
			menu_handle_press(px, py);
		menu_draw();
	}
}