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

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "display.h"
#include "font7.h"
#include "bip39.h"
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

static void kp_draw_header(const char *title, const char *echo, int echo_len,
                           int mask)
{
	lcd_fill(C_BG);
	if (title) lcd_line(2, 2, title, C_LBL, C_BG);
	if (echo) {
		char line[40];
		int n = (echo_len > 20) ? 20 : echo_len;
		for (int i = 0; i < n; i++) line[i] = mask ? '*' : echo[i];
		line[n] = '\0';
		if (mask)
			lcd_line(2, 16, line, C_FG, C_BG);
		else
			lcd_line_big(2, 14, line, C_FG, C_BG);
	}
}

static void kp_draw(const char *title, const char *echo, int echo_len,
                    int mask)
{
	kp_draw_header(title, echo, echo_len, mask);
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

int kp_capture(const char *title, char *out, int max, int numeric_only,
               int mask)
{
	int len = 0;
	out[0] = '\0';
	for (;;) {
		kp_draw(title, out, len, mask);
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

/* ------------------------------------------------------------------ *
 * Alpha swipe-to-select (recovery phrase entry).
 *
 * The finger drags over the letters; the hovered cell is highlighted and
 * a big floating preview of the candidate appears in the box between the
 * title and the grid. Lifting commits the hovered character (or triggers
 * the hovered action key). Brightened box = current echo is up top.
 * ------------------------------------------------------------------ */

#define PREV_X0 78
#define PREV_X1 162
#define PREV_Y0 34
#define PREV_Y1 112

static void kp_paint_cell(const kp_cell *c, int highlight)
{
	const char *lbl = kp_label(c->kind);
	int is_action = (c->kind < 0);
	uint16_t bg = is_action ? 0x0842 : C_BTN;
	if (c->kind == KEY_ENTER) bg = 0x03EF;
	if (highlight) bg = C_FG;   /* bright box under the finger */
	lcd_rect_text(c->x0, c->y0, c->x1, c->y1, lbl, C_FG, bg);
}

static void kp_float_box(int ch)
{
	/* clear the preview region; no colored outline block */
	lcd_rect(PREV_X0, PREV_Y0, PREV_X1, PREV_Y1, C_BG);
	if (ch < 0 || ch == KEY_SPACE) return;
	/* high-res 8x16 glyph at scale 3 -> 24x48, centered in 84x78 box */
	int scale = 3;
	int tw = F8_W * scale, th = F8_H * scale;
	int cx = PREV_X0 + ((PREV_X1 - PREV_X0) - tw) / 2;
	int cy = PREV_Y0 + ((PREV_Y1 - PREV_Y0) - th) / 2;
	lcd_gl8x16(cx, cy, (char)ch, C_FG, C_BG, scale);
}

static int kp_hit(kp_cell *cells, int n, int x, int y)
{
	for (int i = 0; i < n; i++)
		if (ui_pt_in(x, y, cells[i].x0, cells[i].y0,
		             cells[i].x1, cells[i].y1)) return i;
	return -1;
}

int kp_capture_alpha(const char *title, char *out, int max)
{
	s_mode = 1;   /* force the alphabetic keypad layout */
	kp_cell cells[40];
	int n = kp_build(cells, 40);
	int len = 0;
	out[0] = '\0';

	/* static fg/bg colors the grid uses */
	lcd_fill(C_BG);
	kp_draw_header(title, out, 0, 0);
	kp_float_box(' ');
	for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);

	int hover = -1;
	bool down = false;
	for (;;) {
		int cx, cy;
		bool pressed = ui_touch_now(&cx, &cy);
		if (pressed) {
			down = true;
			int h = kp_hit(cells, n, cx, cy);
			if (h != hover) {
				if (hover >= 0) kp_paint_cell(&cells[hover], 0);
				hover = h;
				if (hover >= 0) {
					kp_paint_cell(&cells[hover], 1);
					if (cells[hover].kind >= 0 && cells[hover].kind != KEY_SPACE)
						kp_float_box(cells[hover].kind);
					else
						kp_float_box(KEY_SPACE);
				}
			}
		} else if (down) {
			down = false;
			if (hover >= 0) {
				int kind = cells[hover].kind;
				kp_paint_cell(&cells[hover], 0);
				hover = -1;
				if (kind == KEY_ENTER) { out[len] = '\0'; return 0; }
				if (kind == KEY_BACK) {
					if (len > 0) len--;
					out[len] = '\0';
				} else if (kind == KEY_SPACE) {
					if (len < max - 1) out[len++] = ' ';
					out[len] = '\0';
				} else if (kind >= 0) {
					if (len >= max - 1) continue;
					out[len++] = (char)kind;
					out[len] = '\0';
				}
				kp_draw_header(title, out, len, 0);
				kp_float_box(' ');
				for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);
			}
		}
		vTaskDelay(pdMS_TO_TICKS(8));
	}
}

/* ------------------------------------------------------------------ *
 * Word-by-word mnemonic recovery.
 *
 * Each BIP39 word is uniquely identified by its first 4 letters (or, for a
 * short terminal word, the whole word). The user swipes the letters of a
 * prefix; as soon as it is unambiguous the keypad resolves it to the full
 * word, inserts it into the phrase and advances. DEL removes the last letter
 * (or the last finished word when the current word is empty); the action key
 * (OK) finishes the phrase.
 * ------------------------------------------------------------------ */

#define WORD_BUF_MAX 8   /* longest typed prefix we keep around */

/* Append a resolved word index to the phrase string, space separated. */
static void word_append(char *out, int *len, int max, int wi)
{
	const char *w = os_bip39_word_at(wi);
	if (!w) return;
	size_t wl = strlen(w);
	if (*len + (int)wl + 2 > max) return;
	if (*len > 0) out[(*len)++] = ' ';
	memcpy(out + *len, w, wl);
	*len += (int)wl;
	out[*len] = '\0';
}

/* Draw the phrase header: title, word count, and a hint line. The current
 * prefix (and the hovered letter) live in the floating preview box, so we
 * keep the header to the two top lines (y<=30, above PREV_Y0=34). */
static void kp_draw_phrase_header(const char *title, int nwords)
{
	lcd_fill(C_BG);
	if (title) lcd_line(2, 2, title, C_LBL, C_BG);
	char line[40];
	if (nwords > 0) {
		snprintf(line, sizeof line, "%d word%s in", nwords,
		         nwords == 1 ? "" : "s");
		lcd_line(2, 14, line, C_DIM, C_BG);
	} else {
		lcd_line(2, 14, "type word abbreviations", C_DIM, C_BG);
	}
}

/* Floating preview: hovered letter (large), current typed prefix, or the
 * last word resolved from a prefix (shown as confirmation until the user
 * starts the next word). */
static void kp_float_preview(int ch, const char *cur, int ncur, int prev_wi)
{
	lcd_rect(PREV_X0, PREV_Y0, PREV_X1, PREV_Y1, C_BG);
	if (ch > 0 && ch != KEY_SPACE) {           /* hovered key */
		char s[2] = { (char)ch, '\0' };
		int scale = 3;
		int tw = F8_W * scale, th = F8_H * scale;
		int cx = PREV_X0 + ((PREV_X1 - PREV_X0) - tw) / 2;
		int cy = PREV_Y0 + ((PREV_Y1 - PREV_Y0) - th) / 2;
		lcd_gl8x16(cx, cy, s[0], C_FG, C_BG, scale);
	} else if (ncur > 0) {           /* prefix in progress */
		char s[5];
		int n = ncur < 4 ? ncur : 4;
		for (int i = 0; i < n; i++) s[i] = cur[i];
		s[n] = '\0';
		lcd_line_big(PREV_X0 + 4, PREV_Y0 +
		             ((PREV_Y1 - PREV_Y0) - FONT_CHAR_H * 2) / 2,
		             s, C_FG, C_BG);
	} else if (prev_wi >= 0) {       /* resolved word confirmation */
		lcd_line_big(PREV_X0 + 4, PREV_Y0 +
		             ((PREV_Y1 - PREV_Y0) - FONT_CHAR_H * 2) / 2,
		             os_bip39_word_at(prev_wi), C_FG, C_BG);
	}
}

int kp_capture_phrase(const char *title, char *out, int max)
{
	s_mode = 1;
	kp_cell cells[40];
	int n = kp_build(cells, 40);

	char cur[WORD_BUF_MAX + 1];
	int ncur = 0;
	cur[0] = '\0';
	int prev_wi = -1;              /* last resolved word, shown as confirmation */
	int outlen = 0;
	int nwords = 0;
	out[0] = '\0';

	lcd_fill(C_BG);
	kp_draw_phrase_header(title, 0);
	kp_float_preview(KEY_SPACE, cur, ncur, prev_wi);
	for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);

	int hover = -1;
	bool down = false;
	int settle = 0;              /* consecutive touch samples before a press */
	int lost = 0;                /* consecutive misses before a release */
	TickType_t last_commit = 0;  /* ghost-tap lockout */

	for (;;) {
		int cx, cy;
		bool got = ui_touch_now(&cx, &cy);
		if (got) {
			if (!down) {
				/* debounced press: only believe a finger after 3
				 * consecutive reads land on a key (the CST816D
				 * ghosts single-sample touches near a lift) */
				int h = kp_hit(cells, n, cx, cy);
				if (h >= 0) {
					if (++settle >= 3) {
						down = true;
						settle = 0;
						lost = 0;
						hover = h;
						kp_paint_cell(&cells[hover], 1);
						kp_float_preview(cells[hover].kind, cur, ncur, prev_wi);
					}
				} else {
					settle = 0;
				}
			} else {
				/* already down: track hover as the finger moves */
				lost = 0;
				int h = kp_hit(cells, n, cx, cy);
				if (h != hover) {
					if (hover >= 0) kp_paint_cell(&cells[hover], 0);
					hover = h;
					if (hover >= 0) {
						kp_paint_cell(&cells[hover], 1);
						kp_float_preview(cells[hover].kind, cur, ncur, prev_wi);
					}
				}
			}
		} else if (down) {
			/* debounced release: commit only after the finger is gone
			 * for 3 consecutive polls (same lost>=3 rule as the rest
			 * of the UI) */
			if (++lost < 3)
				goto tick;
			down = false;
			lost = 0;
			settle = 0;
			if (hover < 0)
				goto tick;
			/* ghost-tap lockout: ignore a release that follows the last
			 * commit by less than 120ms — the CST816D re-reports the
			 * same point as the finger lifts off a key */
			if (xTaskGetTickCount() - last_commit < pdMS_TO_TICKS(120))
				goto tick;
			last_commit = xTaskGetTickCount();
			{
				int kind = cells[hover].kind;
				kp_paint_cell(&cells[hover], 0);
				hover = -1;
				if (kind == KEY_BACK) {
					/* drop a letter, or the last committed word */
					if (ncur > 0) {
						cur[--ncur] = '\0';
					} else if (nwords > 0) {
						/* back out the last word from the phrase */
						int i = outlen;
						if (i > 0 && out[i - 1] == ' ') i--;
						while (i > 0 && out[i - 1] != ' ') i--;
						outlen = i;
						out[outlen] = '\0';
						nwords--;
					}
				} else if (kind == KEY_SPACE) {
					/* commit the prefix as an exact word if it is a complete
					 * word the auto-resolve left open (short words whose 4th
					 * letter points at a longer word, e.g. "add" vs "addict") */
					int wi = (ncur > 0) ? os_bip39_word_index(cur) : -1;
					if (wi >= 0) {
						word_append(out, &outlen, max, wi);
						nwords++;
						prev_wi = wi;
						cur[0] = '\0';
						ncur = 0;
					}
				} else if (kind == KEY_ENTER) {
					out[outlen] = '\0';
					return (outlen > 0) ? 0 : -1;
				} else if (kind >= 0) {
					/* append a letter; BIP39 words are lowercase so fold the
					 * keypad's uppercase cell into lower case for matching */
					if (ncur < WORD_BUF_MAX) {
						char c = (char)kind;
						if (c >= 'A' && c <= 'Z')
							c = (char)(c - 'A' + 'a');
						cur[ncur++] = c;
						cur[ncur] = '\0';
						prev_wi = -1;    /* start of a new prefix */
					}
				}
			}
			/* auto-resolve an unambiguous prefix -> committed word */
			if (ncur >= 1 && ncur <= 4) {
				int wi = os_bip39_word_try_commit(cur, ncur);
				if (wi >= 0) {
					word_append(out, &outlen, max, wi);
					nwords++;
					prev_wi = wi;
					cur[0] = '\0';
					ncur = 0;
				}
			}
			if (xTaskGetTickCount() - last_commit < pdMS_TO_TICKS(120))
				goto tick;
			last_commit = xTaskGetTickCount();
			kp_draw_phrase_header(title, nwords);
			kp_float_preview(KEY_SPACE, cur, ncur, prev_wi);
			for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);
		}
tick:
		vTaskDelay(pdMS_TO_TICKS(8));
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
	if (kp_capture("SET PIN  (numeric)", p1, OS_PIN_MAX_LEN + 1, 1, 1) != 0) {
		os_secure_bzero(p1, sizeof(p1));
		return -1;
	}
	lcd_fill(C_BG);
	if (kp_capture("CONFIRM PIN", p2, OS_PIN_MAX_LEN + 1, 1, 1) != 0) {
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
	if (kp_capture("ENTER PIN", p, OS_PIN_MAX_LEN + 1, 1, 1) != 0)
		return -1;
	if (out && out_max > (int)strlen(p)) {
		strcpy(out, p);
		os_secure_bzero(p, sizeof(p));
		return (int)strlen(out);
	}
	os_secure_bzero(p, sizeof(p));
	return -1;
}