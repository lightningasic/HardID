/*
 * HardID — shared touch/input interaction primitives
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "display.h"
#include "touch.h"
#include "inter.h"

bool ui_pt_in(int x, int y, int x0, int y0, int x1, int y1)
{
	return x >= x0 && x < x1 && y >= y0 && y < y1;
}

bool ui_wait_press(int *px, int *py)
{
	int x, y;
	int settle = 0;
	for (;;) {
		if (touch_get(&x, &y)) {
			if (++settle >= 3) { *px = x; *py = y; return true; }
		} else {
			settle = 0;
		}
		vTaskDelay(pdMS_TO_TICKS(8));
	}
}

bool ui_wait_press_to(int *px, int *py, uint32_t timeout_ms)
{
	int x, y;
	int settle = 0;
	uint32_t elapsed = 0;
	for (;;) {
		if (touch_get(&x, &y)) {
			if (++settle >= 3) { *px = x; *py = y; return true; }
		} else {
			settle = 0;
		}
		if (timeout_ms > 0) {
			elapsed += 8;
			if (elapsed >= timeout_ms)
				return false;
		}
		vTaskDelay(pdMS_TO_TICKS(8));
	}
}

void ui_wait_release(int *rx, int *ry)
{
	int x, y;
	int lost = 0;
	for (;;) {
		if (touch_get(&x, &y)) {
			*rx = x; *ry = y;
			lost = 0;
		} else if (++lost >= 3) {
			break;
		}
		vTaskDelay(pdMS_TO_TICKS(8));
	}
}

void ui_wait_ack(void)
{
	/* Explicit BACK button instead of an invisible "tap anywhere": every
	 * info screen gets a consistent, visible way back to the caller. */
	lcd_rect_text(60, 288, 180, 318, "BACK", C_FG, C_BTN);
	int x, y;
	for (;;) {
		ui_wait_press(&x, &y);
		int rx = x, ry = y;
		ui_wait_release(&rx, &ry);
		if (ui_pt_in(x, y, 60, 288, 180, 318) &&
		    ui_pt_in(rx, ry, 60, 288, 180, 318))
			return;
	}
}

bool ui_touch_now(int *px, int *py)
{
	int x, y;
	if (!touch_get(&x, &y))
		return false;
	if (px) *px = x;
	if (py) *py = y;
	return true;
}