/*
 * HardID — on-screen user interface (menu + alphanumeric keypad)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Three-function Trezor-style framework driven entirely by touch:
 *   1. Initialize   — generate seed, show recovery phrase, set PIN
 *   2. Sign         — unlock w/ PIN, sign a fixed digest, show sig
 *   3. Factory reset— confirm, wipe SE state
 *
 * On-screen keypad has numeric and alphabetic pages (toggle), so no
 * physical buttons are required. Touch model: press latches a key region;
 * the key fires only if the finger is released inside the same region.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_random.h"

#include "display.h"
#include "touch.h"
#include "ui.h"
#include "boot.h"
#include "se_driver.h"
#include "seed.h"
#include "bip39.h"
#include "bip32.h"
#include "pin.h"
#include "secure_zero.h"

/* mock-SE helpers (se_mock.c); a real backend exposes wipe via se_driver_t */
void se_mock_reset(void);
void se_mock_set_pin(const uint8_t *pin, size_t len);

#define C_BG   0x0000
#define C_FG   0xFFFF
#define C_BTN  0x1D8F
#define C_LBL  0xE73C
#define C_OK   0x07E0
#define C_ERR  0xF800
#define C_DIM  0x8410
#define C_WARN 0xFD20

/* special key codes (negative; positive = ASCII char) */
#define KEY_BACK   (-1)
#define KEY_ENTER  (-2)
#define KEY_TOGGLE (-3)
#define KEY_SPACE  (' ')

#define KP_TOP      120          /* keypad area starts here */
#define KP_ROW_H    38
#define KP_NUM_COLS 3
#define KP_ALPHA_COLS 6
#define KP_CELL_W   (240 / KP_ALPHA_COLS)   /* 40 */

/* ---- touch primitives ---- */

static bool pt_in(int x, int y, int x0, int y0, int x1, int y1)
{
	return x >= x0 && x < x1 && y >= y0 && y < y1;
}

/* Wait for a touch press, return its position (blocking, polled). */
static bool touch_wait_press(int *px, int *py)
{
	int x, y;
	for (;;) {
		if (touch_get(&x, &y)) { *px = x; *py = y; return true; }
		vTaskDelay(pdMS_TO_TICKS(10));
	}
}

/* Wait until the finger lifts. Returns true if (x,y) at release. */
static void touch_wait_release(int *rx, int *ry)
{
	int x, y;
	for (;;) {
		if (!touch_get(&x, &y)) break;
		*rx = x; *ry = y;
		vTaskDelay(pdMS_TO_TICKS(10));
	}
}

/* ---- keypad cell model ---- */

typedef struct {
	int kind;      /* ascii char or KEY_* constant */
	int x0, y0, x1, y1;
} kp_cell;

static int s_mode = 0;   /* 0 numeric, 1 alpha */

/* Build the cell list for the current mode. Returns cell count. */
static int kp_build(kp_cell *cells, int maxcells)
{
	int n = 0;
	if (s_mode == 0) {
		/* numeric: 4 rows of 3 + a bottom action row */
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
		/* action row: [abc] [del] [enter] */
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
		/* alpha: 26 letters in 6 cols x 5 rows. Rows 0-3 hold A..X
		 * (24 letters), row 4: Y Z + [space][DEL][OK][123]. */
		static const char alpha[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		int idx = 0;
		for (int r = 0; r < 5; r++) {
			for (int c = 0; c < KP_ALPHA_COLS; c++) {
				if (n >= maxcells) return n;
				int kind;
				if (r == 4) {
					/* last row: 2 letters + 4 actions */
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

/* Label for a cell. */
static const char *kp_label(int kind)
{
	switch (kind) {
	case KEY_BACK:   return "DEL";
	case KEY_ENTER:  return "OK";
	case KEY_TOGGLE: return s_mode ? "123" : "ABC";
	case KEY_SPACE:  return "SPC";
	default:
		/* single char -> tiny static buffer */
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
	/* echo line */
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

/* Capture a string via the keypad. Returns 0 on OK, -1 on cancel/timeout. */
static int kp_capture(const char *title, char *out, int max,
                      int numeric_only)
{
	int len = 0;
	out[0] = '\0';
	for (;;) {
		kp_draw(title, out, len);
		int px, py;
		touch_wait_press(&px, &py);
		/* identify pressed cell */
		kp_cell cells[40];
		int n = kp_build(cells, 40);
		int hit = -1;
		for (int i = 0; i < n; i++)
			if (pt_in(px, py, cells[i].x0, cells[i].y0,
			          cells[i].x1, cells[i].y1)) { hit = i; break; }
		int rx = px, ry = py;
		touch_wait_release(&rx, &ry);
		if (hit < 0) continue;  /* pressed outside — ignore */
		kp_cell *c = &cells[hit];
		if (!pt_in(rx, ry, c->x0, c->y0, c->x1, c->y1))
			continue;           /* slid away — cancel */
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
		/* character */
		if (len >= max - 1) continue;
		if (numeric_only && !(kind >= '0' && kind <= '9')) continue;
		out[len++] = (char)kind;
		out[len] = '\0';
	}
}

/* ---- confirmation dialog ---- */

static bool confirm(const char *msg)
{
	lcd_fill(C_BG);
	lcd_text_wrap(2, 10, msg, C_WARN, C_BG);
	/* two buttons */
	lcd_rect_text(15, 200, 115, 250, "Cancel", C_FG, C_BTN);
	lcd_rect_text(125, 200, 225, 250, "Confirm", C_FG, C_ERR);
	for (;;) {
		int px, py;
		touch_wait_press(&px, &py);
		int rx = px, ry = py;
		touch_wait_release(&rx, &ry);
		if (pt_in(px, py, 125, 200, 225, 250) &&
		    pt_in(rx, ry, 125, 200, 225, 250))
			return true;
		if (pt_in(px, py, 15, 200, 115, 250) &&
		    pt_in(rx, ry, 15, 200, 115, 250))
			return false;
	}
}

/* Confirmation drawn over existing content (does not clear the screen).
 * Returns true on Confirm. */
static bool confirm_overlay(void)
{
	lcd_rect_text(15, 200, 115, 250, "Cancel", C_FG, C_BTN);
	lcd_rect_text(125, 200, 225, 250, "Confirm", C_FG, C_ERR);
	for (;;) {
		int px, py;
		touch_wait_press(&px, &py);
		int rx = px, ry = py;
		touch_wait_release(&rx, &ry);
		if (pt_in(px, py, 125, 200, 225, 250) &&
		    pt_in(rx, ry, 125, 200, 225, 250))
			return true;
		if (pt_in(px, py, 15, 200, 115, 250) &&
		    pt_in(rx, ry, 15, 200, 115, 250))
			return false;
	}
}

/* ---- PIN (via keypad) ---- */

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

/* ---- sign a fixed test digest ---- */

static void screen_fixed_digest_sign(void)
{
	const se_driver_t *se = se_active();
	uint8_t digest[32], sig[64];
	memset(digest, 0x11, sizeof(digest));

	bool initd;
	se->is_initialized(&initd);
	if (!initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Not initialized. Run Initialize first.", C_WARN, C_BG);
		return;
	}

	/* 1. enter PIN and verify against SE */
	lcd_fill(C_BG);
	lcd_line(2, 2, "Unlock to sign", C_LBL, C_BG);
	char pin[OS_PIN_MAX_LEN + 1];
	int n = ui_enter_pin(pin, sizeof(pin));
	if (n < 0) { lcd_text_wrap(2, 16, "cancelled", C_ERR, C_BG); return; }

	uint32_t wait;
	bool duress;
	int vr = se->verify_pin((const uint8_t *)pin, n, &wait, &duress);
	os_secure_bzero(pin, sizeof(pin));
	if (vr != SE_OK) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "wrong PIN", C_ERR, C_BG);
		return;
	}

	/* 2. sign */
	uint8_t recid;
	int r = se->sign_digest(NULL, 0, digest, sig, &recid);
	lcd_fill(C_BG);
	if (r != SE_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "sign failed rc=%d", r);
		lcd_text_wrap(2, 10, msg, C_ERR, C_BG);
		return;
	}
	lcd_line(2, 2, "Signature (r||s)", C_LBL, C_BG);
	char hex[130];
	for (int i = 0; i < 64; i++)
		snprintf(hex + i * 2, 3, "%02x", sig[i]);
	lcd_text_wrap(2, 16, hex, C_FG, C_BG);
}

/* ---- factory reset ---- */

static void screen_factory_reset(void)
{
	if (!confirm("Wipe device? Seed + PIN will be erased.")) {
		lcd_text_wrap(2, 100, "cancelled", C_FG, C_BG);
		return;
	}
	/* wipe via the SE */
	se_mock_reset();
	os_board_display_home();
	lcd_text_wrap(2, 60, "Device wiped. Re-initialize to set a seed.", C_OK, C_BG);
}

/* ---- initialize ---- */

static void screen_initialize(void)
{
	const se_driver_t *se = se_active();
	bool initd;
	se->is_initialized(&initd);
	if (initd) {
		lcd_fill(C_BG);
		lcd_text_wrap(2, 10, "Device already initialized. Wipe to re-seed.", C_WARN, C_BG);
		return;
	}

	uint8_t seed32[OS_SEED_LEN], seed64[OS_BIP39_SEED_LEN], host[32];
	char mnemonic[OS_BIP39_MNEMONIC_MAX];

	esp_fill_random(host, sizeof(host));
	if (os_seed_generate(host, sizeof(host), seed32) != 0) {
		lcd_text_wrap(2, 10, "seed gen failed", C_ERR, C_BG);
		return;
	}

	/* 1. show recovery phrase, user confirms (buttons overlay the phrase
	 * so the user can write it down while the confirmation is on screen) */
	os_bip39_entropy_to_mnemonic(seed32, sizeof(seed32),
	                             mnemonic, sizeof(mnemonic));
	os_bip39_mnemonic_to_seed(mnemonic, NULL, seed64);
	lcd_fill(C_BG);
	lcd_line(2, 2, "Recovery phrase", C_LBL, C_BG);
	lcd_text_wrap(2, 16, mnemonic, C_FG, C_BG);
	if (!confirm_overlay()) {
		os_secure_bzero(seed32, sizeof(seed32));
		os_secure_bzero(seed64, sizeof(seed64));
		return;
	}

	/* 2. set PIN */
	lcd_fill(C_BG);
	char pin[OS_PIN_MAX_LEN + 1];
	int pin_len = ui_set_pin(pin, sizeof(pin));
	if (pin_len < 0) {
		lcd_text_wrap(2, 80, "PIN setup failed", C_ERR, C_BG);
		return;
	}
	/* mock stores the PIN for verify_pin; encode as ASCII digits.
	 * (real SE sets the PIN in hardware) */
	se_mock_set_pin((const uint8_t *)pin, (size_t)pin_len);
	os_secure_bzero(pin, sizeof(pin));

	/* 3. store seed in SE */
	int rc = se->store_seed(seed32);
	lcd_fill(C_BG);
	if (rc != SE_OK) {
		lcd_text_wrap(2, 10, "store seed failed", C_ERR, C_BG);
	} else {
		lcd_text_wrap(2, 10, "Initialized OK. Seed + PIN stored.", C_OK, C_BG);
	}
	os_secure_bzero(seed32, sizeof(seed32));
	os_secure_bzero(seed64, sizeof(seed64));
	os_secure_bzero(host, sizeof(host));
}

/* ---- main menu ---- */

static void menu_draw(void)
{
	lcd_fill(C_BG);
	lcd_line(2, 2, "HardID", C_LBL, C_BG);
	lcd_line(2, 14, "tap an action", C_DIM, C_BG);
	lcd_rect_text(15, 60, 225, 120, "1  Initialize", C_FG, C_BTN);
	lcd_rect_text(15, 140, 225, 200, "2  Sign", C_FG, C_BTN);
	lcd_rect_text(15, 220, 225, 280, "3  Factory reset", C_FG, C_BTN);
}

static void menu_handle_press(int px, int py)
{
	if (pt_in(px, py, 15, 60, 225, 120))       screen_initialize();
	else if (pt_in(px, py, 15, 140, 225, 200)) screen_fixed_digest_sign();
	else if (pt_in(px, py, 15, 220, 225, 280)) screen_factory_reset();
}

void ui_run(void)
{
	menu_draw();
	for (;;) {
		int px, py;
		if (touch_wait_press(&px, &py)) {
			int rx = px, ry = py;
			touch_wait_release(&rx, &ry);
			/* only fire if released inside same button */
			if (pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
			    (rx == px && ry == py))
				menu_handle_press(px, py);
			menu_draw();
		}
	}
}