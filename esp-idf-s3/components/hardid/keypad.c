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

#include "esp_log.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "display.h"
#include "font7.h"
#include "lang.h"
#include "bip39.h"
#include "devcfg.h"
#include "pin.h"
#include "secure_zero.h"
#include "inter.h"
#include "keypad.h"

#define C_BG   0x0000
#define C_FG   0xFFFF
#define C_BTN  0x039E  /* brand blue: the logo bolt (0,113,242) */
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

static int s_mode = 0;   /* 0 numeric, 1 upper, 2 lower, 3 digits+symbols */
static int s_cycle3 = 0; /* passphrase capture cycles pages 1->2->3->1 */

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
		/* Character pages: 1 = A-Z, 2 = a-z, 3 = digits + symbols.
		 * kp_capture (PIN/RESET) only ever uses modes 0/1; the 3-page
		 * cycle is armed by kp_capture_alpha (passphrase entry), where
		 * the toggle key rotates 1 -> 2 -> 3 -> 1. BIP39 passphrases are
		 * case-sensitive arbitrary UTF-8, so an uppercase-only page would
		 * silently shrink the user's keyspace. Page 3 holds 26 chars:
		 * 10 digits + 16 common symbols. */
		static const char page_upper[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		static const char page_lower[26] = "abcdefghijklmnopqrstuvwxyz";
		static const char page_sym[26]   = "0123456789!@#$%^&*()-_=+,.";
		const char *alpha = (s_mode == 2) ? page_lower :
		                    (s_mode == 3) ? page_sym : page_upper;
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
	case KEY_BACK:   return os_lang_str(LKEY_DEL);
	case KEY_ENTER:  return os_lang_str(LKEY_OK);
	case KEY_TOGGLE:
		/* label names the page the toggle will move TO */
		if (s_mode == 0) return "ABC";
		if (s_cycle3) {
			if (s_mode == 1) return "abc";
			if (s_mode == 2) return "1#$";
			return "ABC";
		}
		return "123";
	case KEY_SPACE:  return os_lang_str(LKEY_SPC);
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
	if (title) lcd_utf8_str(2, 2, title, C_LBL, C_BG, 1);
	if (echo) {
		char line[40];
		int n = (echo_len > 20) ? 20 : echo_len;
		for (int i = 0; i < n; i++) line[i] = mask ? '*' : echo[i];
		line[n] = '\0';
		if (mask)
			lcd_line(2, 22, line, C_FG, C_BG);
		else
			lcd_line_big(2, 20, line, C_FG, C_BG);
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
		lcd_rect_text_utf8(cells[i].x0, cells[i].y0, cells[i].x1, cells[i].y1,
		                   lbl, C_FG, bg);
	}
}

int kp_capture(const char *title, char *out, int max, int numeric_only,
               int mask)
{
	/* numeric-only entries (PIN) always start on the digit page; anything
	 * else (e.g. typing RESET) starts on the alphabetic page */
	s_mode = numeric_only ? 0 : 1;
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
	lcd_rect_text_utf8(c->x0, c->y0, c->x1, c->y1, lbl, C_FG, bg);
}

/* Render one character big, centered in the preview box. font8x16 only
 * covers A-Z/space; lowercase, digits and symbols fall back to font7
 * (full printable ASCII) at a matching scale so every passphrase page
 * previews what is under the finger. */
static void kp_big_char(int x0, int y0, int x1, int y1, int ch)
{
	if (ch >= 'A' && ch <= 'Z') {
		int scale = 4;   /* 8x16 -> 32x64: the largest that fits the box */
		int tw = F8_W * scale, th = F8_H * scale;
		int cx = x0 + ((x1 - x0) - tw) / 2;
		int cy = y0 + ((y1 - y0) - th) / 2;
		lcd_gl8x16(cx, cy, (char)ch, C_FG, C_BG, scale);
	} else {
		int scale = 6;   /* font7: 5x7 -> 30x42, fits the 84x78 box */
		int tw = FONT_CHAR_W * scale, th = FONT_CHAR_H * scale;
		int cx = x0 + ((x1 - x0) - tw) / 2;
		int cy = y0 + ((y1 - y0) - th) / 2;
		char s[2] = { (char)ch, '\0' };
		lcd_line_scaled(cx, cy, s, C_FG, C_BG, scale);
	}
}

static void kp_float_box(int ch)
{
	/* clear the preview region; no colored outline block */
	lcd_rect(PREV_X0, PREV_Y0, PREV_X1, PREV_Y1, C_BG);
	if (ch < 0 || ch == KEY_SPACE) return;
	kp_big_char(PREV_X0, PREV_Y0, PREV_X1, PREV_Y1, ch);
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
	s_mode = 1;     /* start on the uppercase page */
	s_cycle3 = 1;   /* toggle cycles upper -> lower -> digits/symbols */
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
				if (kind == KEY_ENTER) {
					out[len] = '\0';
					s_mode = 1; s_cycle3 = 0;
					return 0;
				}
				if (kind == KEY_TOGGLE) {
					s_mode = (s_mode % 3) + 1;   /* 1->2->3->1 */
					n = kp_build(cells, 40);
				} else if (kind == KEY_BACK) {
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
 * word and SHOWS it — the "WORD N" counter does NOT advance yet, so the
 * shown word clearly reads as the CURRENT word. Pressing OK confirms the
 * shown word and only then does the counter advance. OK with no pending
 * word finishes the phrase once the word count is legal. DEL removes the
 * last letter, or backs out of the pending word, or removes the last
 * finished word when the current word is empty.
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

/* True if `count` is a legal BIP39 mnemonic length (a mnemonic is 12, 15,
 * 18, 21, or 24 words). */
static bool kp_legal_word_count(int count)
{
	/* DEV-ONLY: 4-word test seeds (no checksum) are legal in test-seed
	 * builds so the brain-phrase flow can be exercised quickly. */
	if (os_dev_test_seed_enabled() && count == 4)
		return true;
	return count == 12 || count == 15 || count == 18 ||
	       count == 21 || count == 24;
}

/* Draw the whole phrase-entry area above the key grid. One function draws
 * everything so the state can never half-render:
 *   - title + "WORD N" (ALWAYS shown — even alongside a hint, so the user
 *     never loses track of which word they are on)
 *   - the current prefix, echoed big next to the counter
 *   - hint (red) when given, else the auto-resolved PENDING word shown big
 *     (still on the SAME "WORD N" counter until OK commits it), else the
 *     LIVE CANDIDATE LIST: every wordlist word starting with the current
 *     prefix, from the very first letter (3 cols x 8 rows of small text,
 *     "+N" overflow note). */
static void kp_draw_phrase_area(const char *title, int nwords,
                                const char *cur, int ncur, int pending_wi,
                                const char *hint)
{
	/* Clear only down to the top of the key grid: a full lcd_fill would
	 * repaint every key on each keypress and visibly flicker. */
	lcd_rect(0, 0, 240, KP_TOP, C_BG);
	if (title) lcd_utf8_str(2, 2, title, C_LBL, C_BG, 1);
	char line[40];
	snprintf(line, sizeof line, os_lang_str(LKEY_WORD_N), nwords + 1);
	lcd_utf8_str(2, 16, line, C_FG, C_BG, 1);
	if (ncur > 0) {
		char p[WORD_BUF_MAX + 2];
		int m = ncur < WORD_BUF_MAX ? ncur : WORD_BUF_MAX;
		memcpy(p, cur, m);
		p[m] = '_'; p[m + 1] = '\0';
		lcd_line_big(100, 14, p, C_WARN, C_BG);
	}
	if (hint) {
		lcd_utf8_str(2, 36, hint, C_ERR, C_BG, 1);
		return;
	}
	if (pending_wi >= 0) {
		/* Auto-resolved word, NOT yet committed: show it big against the
		 * SAME "WORD N" counter so it reads as the current word, not the
		 * next one. The counter advances only when OK commits it. */
		lcd_line_big(PREV_X0 + 4,
		             PREV_Y0 + ((PREV_Y1 - PREV_Y0) - FONT_CHAR_H * 2) / 2,
		             os_bip39_word_at(pending_wi), C_FG, C_BG);
	} else if (ncur > 0) {
		int idx[24];
		int total = os_bip39_words_with_prefix(cur, (size_t)ncur, idx, 24);
		int shown = total < 24 ? total : 24;
		for (int i = 0; i < shown; i++) {
			lcd_line(2 + (i % 3) * 80, 36 + (i / 3) * 10,
			         os_bip39_word_at(idx[i]), C_FG, C_BG);
		}
		if (total > shown) {
			/* overwrite the last cell with an overflow note */
			int x = 2 + (23 % 3) * 80, y = 36 + (23 / 3) * 10;
			lcd_rect(x, y, x + 80, y + FONT_CHAR_H, C_BG);
			snprintf(line, sizeof line, "+%d more", total - 23);
			lcd_line(x, y, line, C_DIM, C_BG);
		}
	} else {
		/* idle: nothing typed or resolved yet on this word. Show what to
		 * do next, centred in the box, so the eye lands on an explicit
		 * prompt rather than an empty area. */
		const char *g = (nwords == 0) ? os_lang_str(LKEY_ENTER_WORD)
		                             : os_lang_str(LKEY_ENTER_NEXT_WORD);
		int gw = lcd_utf8_width(g, 1);
		int gx = PREV_X0 + ((PREV_X1 - PREV_X0) - gw) / 2;
		int gy = PREV_Y0 + ((PREV_Y1 - PREV_Y0) - 16) / 2;
		lcd_utf8_str(gx, gy, g, C_DIM, C_BG, 1);
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
	int pending_wi = -1;          /* auto-resolved word shown, awaiting OK */
	int outlen = 0;
	int nwords = 0;
	out[0] = '\0';

	lcd_fill(C_BG);
	kp_draw_phrase_area(title, 0, cur, 0, pending_wi, NULL);
	for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);

	int hover = -1;
	bool down = false;
	int settle = 0;              /* consecutive touch samples before a press */
	int lost = 0;                /* consecutive misses before a release */
	int last_kind = -1;         /* last committed key kind (for repeat lock) */
	TickType_t last_commit = 0;  /* ghost re-press lockout (short window) */

	for (;;) {
		int cx, cy;
		bool got = ui_touch_now(&cx, &cy);
		if (got) {
			if (!down) {
				/* Visual feedback is immediate (first read paints the hover
				 * highlight + floating preview), but the press is only
				 * *armed* (eligible to commit on release) after 3
				 * consecutive reads land on a key. The CST816D ghosts
				 * single-sample touches near a lift, and an unarmed ghost
				 * never commits. */
				int h = kp_hit(cells, n, cx, cy);
				if (h != hover) {
					if (hover >= 0) kp_paint_cell(&cells[hover], 0);
					hover = h;
					if (hover >= 0) {
						kp_paint_cell(&cells[hover], 1);
						kp_float_box(cells[hover].kind);
					}
				}
				if (h >= 0) {
					if (++settle >= 3) {
						settle = 0;
						/* repeat lockout: a ghost lands on the *same* key
						 * immediately after a lift (TTTT). A real next tap
						 * is on a different key, so the 60ms window below
						 * is scoped to the SAME kind — different keys are
						 * always allowed even when typed fast. */
						if (cells[h].kind == last_kind &&
						    xTaskGetTickCount() - last_commit <
							    pdMS_TO_TICKS(60))
							continue;
						down = true;
						lost = 0;
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
						kp_float_box(cells[hover].kind);
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
			{
				int kind = cells[hover].kind;
				kp_paint_cell(&cells[hover], 0);
				hover = -1;
				last_kind = kind;
				if (kind == KEY_BACK) {
					/* drop a letter, or back out of the pending word, or
					 * drop the last committed word */
					if (pending_wi >= 0) {
						pending_wi = -1;
						cur[0] = '\0';
						ncur = 0;
					} else if (ncur > 0) {
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
					/* resolve the current prefix as an EXACT word when
					 * auto-resolve left it open (short words that are also
					 * a prefix of a longer word, e.g. "add" vs "addict");
					 * still shown as pending, still committed only by OK */
					if (pending_wi >= 0) {
						/* already resolved: keep it pending, nothing new */
					} else if (ncur > 0) {
						int wi = os_bip39_word_index(cur);
						if (wi >= 0)
							pending_wi = wi;
					}
				} else if (kind == KEY_ENTER) {
					if (pending_wi >= 0) {
						/* confirm the shown word — ONLY now does the
						 * counter advance */
						word_append(out, &outlen, max, pending_wi);
						nwords++;
						pending_wi = -1;
						cur[0] = '\0';
						ncur = 0;
					} else if (!kp_legal_word_count(nwords)) {
						/* WORD N stays visible next to the hint */
						kp_draw_phrase_area(title, nwords, cur, ncur,
							pending_wi,
							os_dev_test_seed_enabled()
								? os_lang_str(LKEY_NEED_WORDS_DEV)
								: os_lang_str(LKEY_NEED_WORDS));
						for (int i = 0; i < n; i++)
							kp_paint_cell(&cells[i], 0);
						goto tick;
					} else {
						out[outlen] = '\0';
						return (outlen > 0) ? 0 : -1;
					}
				} else if (kind >= 0) {
					/* Append letters up to 4 (a BIP39 word's unique prefix),
					 * folding the keypad's uppercase cell to lowercase. After
					 * the word auto-fills, further letters keep appending to
					 * the prefix (so the user can finish the 4 letters); the
					 * resolved word stays pending until OK commits it. */
					if (ncur < 4) {
						char c = (char)kind;
						if (c >= 'A' && c <= 'Z')
							c = (char)(c - 'A' + 'a');
						cur[ncur++] = c;
						cur[ncur] = '\0';
					}
				}
			}
			/* auto-resolve an unambiguous prefix -> PENDING word (shown,
			 * not committed: the counter only advances on OK). */
			if (pending_wi < 0 && ncur >= 1 && ncur <= 4) {
				int wi = os_bip39_word_try_commit(cur, ncur);
				if (wi >= 0)
					pending_wi = wi;
			}
			last_commit = xTaskGetTickCount();
			kp_draw_phrase_area(title, nwords, cur, ncur, pending_wi, NULL);
			for (int i = 0; i < n; i++) kp_paint_cell(&cells[i], 0);
		}
tick:
		vTaskDelay(pdMS_TO_TICKS(8));
	}
}

bool ui_confirm(const char *msg)
{
	lcd_fill(C_BG);
	lcd_text_wrap_utf8(2, 10, msg, C_WARN, C_BG);
	lcd_rect_text_utf8(15, 200, 115, 250, os_lang_str(LKEY_CANCEL), C_FG, C_BTN);
	lcd_rect_text_utf8(125, 200, 225, 250, os_lang_str(LKEY_CONFIRM), C_FG, C_ERR);
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
	lcd_rect_text_utf8(15, 200, 115, 250, os_lang_str(LKEY_CANCEL), C_FG, C_BTN);
	lcd_rect_text_utf8(125, 200, 225, 250, os_lang_str(LKEY_CONFIRM), C_FG, C_ERR);
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

/* Yes/No question (drawn over existing content). True if "Yes". */
bool ui_confirm_yesno(void)
{
	lcd_rect_text_utf8(15, 200, 115, 250, os_lang_str(LKEY_NO), C_FG, C_BTN);
	lcd_rect_text_utf8(125, 200, 225, 250, os_lang_str(LKEY_YES), C_FG, C_OK);
	for (;;) {
		int px, py;
		ui_wait_press(&px, &py);
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		ESP_LOGW("keypad", "confirm touch: press=%d,%d release=%d,%d",
		         px, py, rx, ry);
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
	if (kp_capture(os_lang_str(LKEY_SET_PIN), p1, OS_PIN_MAX_LEN + 1, 1, 1) != 0) {
		os_secure_bzero(p1, sizeof(p1));
		return -1;
	}
	lcd_fill(C_BG);
	if (kp_capture(os_lang_str(LKEY_CONFIRM_PIN), p2, OS_PIN_MAX_LEN + 1, 1, 1) != 0) {
		os_secure_bzero(p1, sizeof(p1));
		os_secure_bzero(p2, sizeof(p2));
		return -1;
	}
	int rc = -1;
	if (strlen(p1) < OS_PIN_MIN_LEN) {
		lcd_fill(C_BG);
		lcd_text_wrap_utf8(2, 10, os_lang_str(LKEY_PIN_TOO_SHORT), C_ERR, C_BG);
	} else if (strcmp(p1, p2) != 0) {
		lcd_fill(C_BG);
		lcd_text_wrap_utf8(2, 10, os_lang_str(LKEY_PIN_MISMATCH), C_ERR, C_BG);
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
	if (kp_capture(os_lang_str(LKEY_ENTER_PIN), p, OS_PIN_MAX_LEN + 1, 1, 1) != 0)
		return -1;
	if (out && out_max > (int)strlen(p)) {
		strcpy(out, p);
		os_secure_bzero(p, sizeof(p));
		return (int)strlen(out);
	}
	os_secure_bzero(p, sizeof(p));
	return -1;
}