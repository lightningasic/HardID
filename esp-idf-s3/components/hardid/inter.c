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
	lcd_line(2, 308, "tap to return", C_DIM, C_BG);
	int x, y;
	ui_wait_press(&x, &y);
	ui_wait_release(&x, &y);
}