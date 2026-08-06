/*
 * HardID — on-screen alphanumeric keypad + confirmation dialogs
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The keypad is the one input widget on this button-less device. It has a
 * numeric page (3 cols x 4 rows + [ABC][DEL][OK]) and an alphabetic page
 * (6 cols x 5 rows, A-Z + [SPC][DEL][OK][123]) toggled by the page key.
 */

#include <string.h>
#include <stdio.h>

#include "display.h"
#include "pin.h"
#include "secure_zero.h"
#include "inter.h"
#include "keypad.h"

#define C_BG   0x0000
#define C_FG   0xFFFF
#define C_BTN  0x1D8F
#define C_LBL  0xE73C
#define C_ERR  0xF800
#define C_WARN 0xFD20

/* special key codes (negative; positive = ASCII char) */
#define KEY_BACK   (-1)
#define KEY_ENTER  (-2)
#define KEY_TOGGLE (-3)
#define KEY_SPACE  (' ')

#define KP_TOP      120
#define KP_ROW_H    38
#define KP_ALPHA_COLS 6
#define KP_CELL_W   (240 / KP_ALPHA_COLS)   /* 40 */

typedef struct {
	int kind;
	int x0, y0, x1, y1;
} kp_cell;

static int s_mode = 0;   /* 0 numeric, 1 alpha */

static int kp_build(kp_cell *cells, int maxcells)
{
	int n = 0;
	if (s_mode == 0) {
		static const char *nums[4][3] = {
			{"1","2","3"},{"4","5","6"},{"7","8","9"},{"0","",""}
		};
		int rows = 4;
		for (int r = 0; r < rows; r++) {
			for (int c = 0; c < 3; c++) {
				const char *lbl = nums[r][c];
				if (!lbl || !*lbl) continue;
				if (n >= maxcells) return n;
				cells[n].kind = lbl[0];
				cells[n].x0 = c * 80;
				cells[n].y0 = KP_TOP + r * KP_ROW_H;
				cells[n].x1 = cells[n].x0 + 80;
				cells[n].y1 = cells[n].y0 + KP_ROW_H;
				n++;
			}
		}
		int r = 4;
		if (n < maxcells) {
			cells[n].kind = KEY_TOGGLE;
			cells[n].x0 = 0;   cells[n].y0 = KP_TOP + r * KP_ROW_H;
			cells[n].x1 = 80;  cells[n].y1 = cells[n].y0 + KP_ROW_H;
			n++;
		}
		if (n < maxcells) {
			cells[n].kind = KEY_BACK;
			cells[n].x0 = 80;  cells[n].y0 = KP_TOP + r * KP_ROW_H;
			cells[n].x1 = 160; cells[n].y1 = cells[n].y0 + KP_ROW_H;
			n++;
		}
		if (n < maxcells) {
			cells[n].kind = KEY_ENTER;
			cells[n].x0 = 160; cells[n].y0 = KP_TOP + r * KP_ROW_H;
			cells[n].x1 = 240; cells[n].y1 = cells[n].y0 + KP_ROW_H;
			n++;
		}
	} else {
		static const char alpha[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		int idx = 0;
		for (int r = 0; r < 5; r++) {
			for (int c = 0; c < KP_ALPHA_COLS; c++) {
				if (n >= maxcells) return n;
				int kind;
				if (r == 4) {
					int act = c - 2;   /* 0=space 1=del 2=ok 3=toggle */
					switch (act) {
					case 0: kind = KEY_SPACE;  break;
					case 1: kind = KEY_BACK;   break;
					case 2: kind = KEY_ENTER;  break;
					case 3: kind = KEY_TOGGLE; break;
					default: kind = '?';
					}
					if (c < 2) {
						kind = (idx < 26) ? alpha[idx] : '?';
						if (idx < 26) idx++;
					}
				} else {
					kind = (idx < 26) ? alpha[idx] : '?';
					if (idx < 26) idx++;
				}
				cells[n].kind = kind;
				cells[n].x0 = c * KP_CELL_W;
				cells[n].y0 = KP_TOP + r * KP_ROW_H;
				cells[n].x1 = cells[n].x0 + KP_CELL_W;
				cells[n].y1 = cells[n].y0 + KP_ROW_H;
				n++;
			}
		}
	}
	return n;
}

static const char *kp_label(int kind)
{
	switch (kind) {
	case KEY_BACK:   return "DEL";
	case KEY_ENTER:  return "OK";
	case KEY_TOGGLE: return s_mode ? "123" : "ABC";
	case KEY_SPACE:  return "SPC";
	default:
		{
			static char b[2];
			b[0] = (char)kind;
			b[1] = '\0';
			return b;
		}
	}
}

static void kp_draw_header(const char *title, const char *echo, int echo_len)
{
	lcd_fill(C_BG);
	if (title) lcd_line(2, 2, title, C_LBL, C_BG);
	if (echo) {
		char line[40];
		int n = echo_len;
		for (int i = 0; i < n && i < 34; i++) line[i] = '*';
		line[(n > 34) ? 34 : n] = '\0';
		lcd_line(2, 16, line, C_FG, C_BG);
	}
}

static void kp_draw(const char *title, const char *echo, int echo_len)
{
	kp_draw_header(title, echo, echo_len);
	kp_cell cells[40];
	int n = kp_build(cells, 40);
	for (int i = 0; i < n; i++) {
		const char *lbl = kp_label(cells[i].kind);
		int is_action = (cells[i].kind < 0);
		uint16_t bg = is_action ? 0x0842 : C_BTN;
		if (cells[i].kind == KEY_ENTER) bg = 0x03EF;
		lcd_rect_text(cells[i].x0, cells[i].y0, cells[i].x1, cells[i].y1,
		              lbl, C_FG, bg);
	}
}

int kp_capture(const char *title, char *out, int max, int numeric_only)
{
	int len = 0;
	out[0] = '\0';
	for (;;) {
		kp_draw(title, out, len);
		int px, py;
		ui_wait_press(&px, &py);
		kp_cell cells[40];
		int n = kp_build(cells, 40);
		int hit = -1;
		for (int i = 0; i < n; i++)
			if (ui_pt_in(px, py, cells[i].x0, cells[i].y0,
			             cells[i].x1, cells[i].y1)) { hit = i; break; }
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (hit < 0) continue;
		kp_cell *c = &cells[hit];
		if (!ui_pt_in(rx, ry, c->x0, c->y0, c->x1, c->y1))
			continue;
		int kind = c->kind;
		if (kind == KEY_TOGGLE) {
			s_mode = !s_mode;
			continue;
		}
		if (kind == KEY_BACK) {
			if (len > 0) { len--; out[len] = '\0'; }
			continue;
		}
		if (kind == KEY_ENTER) {
			out[len] = '\0';
			return 0;
		}
		if (len >= max - 1) continue;
		if (numeric_only && !(kind >= '0' && kind <= '9')) continue;
		out[len++] = (char)kind;
		out[len] = '\0';
	}
}

bool ui_confirm(const char *msg)
{
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, msg, C_WARN, C_BG);
	lcd_rect_text(15, 200, 115, 250, "Cancel", C_FG, C_BTN);
	lcd_rect_text(125, 200, 225, 250, "Confirm", C_FG, C_ERR);
	for (;;) {
		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (ui_pt_in(px, py, 125, 200, 225, 250) &&
		    ui_pt_in(rx, ry, 125, 200, 225, 250))
			return true;
		if (ui_pt_in(px, py, 15, 200, 115, 250) &&
		    ui_pt_in(rx, ry, 15, 200, 115, 250))
			return false;
	}
}

bool ui_confirm_overlay(void)
{
	lcd_rect_text(15, 200, 115, 250, "Cancel", C_FG, C_BTN);
	lcd_rect_text(125, 200, 225, 250, "Confirm", C_FG, C_ERR);
	for (;;) {
		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (ui_pt_in(px, py, 125, 200, 225, 250) &&
		    ui_pt_in(rx, ry, 125, 200, 225, 250))
			return true;
		if (ui_pt_in(px, py, 15, 200, 115, 250) &&
		    ui_pt_in(rx, ry, 15, 200, 115, 250))
			return false;
	}
}

int ui_set_pin(char *out, int out_max)
{
	char p1[OS_PIN_MAX_LEN + 1], p2[OS_PIN_MAX_LEN + 1];
	lcd_fill(C_BG);
	if (kp_capture("SET PIN  (numeric)", p1, OS_PIN_MAX_LEN + 1, 1) != 0) {
		os_secure_bzero(p1, sizeof(p1));
		return -1;
	}
	lcd_fill(C_BG);
	if (kp_capture("CONFIRM PIN", p2, OS_PIN_MAX_LEN + 1, 1) != 0) {
		os_secure_bzero(p1, sizeof(p1));
		os_secure_bzero(p2, sizeof(p2));
		return -1;
	}
	int rc = -1;
	if (strlen(p1) < OS_PIN_MIN_LEN) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "PIN too short (>=4)", C_ERR, C_BG);
	} else if (strcmp(p1, p2) != 0) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "PIN mismatch", C_ERR, C_BG);
	} else if (out && out_max > (int)strlen(p1)) {
		strcpy(out, p1);
		rc = (int)strlen(p1);
	}
	os_secure_bzero(p1, sizeof(p1));
	os_secure_bzero(p2, sizeof(p2));
	return rc;
}

int ui_enter_pin(char *out, int out_max)
{
	char p[OS_PIN_MAX_LEN + 1];
	if (kp_capture("ENTER PIN", p, OS_PIN_MAX_LEN + 1, 1) != 0)
		return -1;
	if (out && out_max > (int)strlen(p)) {
		strcpy(out, p);
		os_secure_bzero(p, sizeof(p));
		return (int)strlen(out);
	}
	os_secure_bzero(p, sizeof(p));
	return -1;
}