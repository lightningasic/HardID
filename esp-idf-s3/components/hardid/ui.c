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

#include "devcfg.h"
#include "display.h"
#include "inter.h"
#include "keypad.h"
#include "pin.h"
#include "se_driver.h"
#include "screen.h"
#include "secure_zero.h"
#include "fido_app.h"
#include "lang.h"
#include "ui.h"

#define MENU_COUNT 10

/* Menu entries in display order; labels are localized via os_lang_str(). */
static const lang_key_t s_menu_keys[MENU_COUNT] = {
	LKEY_INITIALIZE, LKEY_RECOVER, LKEY_SIGN, LKEY_HOST_LINK, LKEY_FIDO,
	LKEY_APP_MARKET, LKEY_PIN, LKEY_ABOUT, LKEY_LANGUAGE, LKEY_FACTORY_RESET,
};

static int s_sel = 0;

/* Build the visible menu for the current device state. INITIALIZE and
 * RECOVER are provisioning actions: on an initialized device they are
 * dead ends ("already initialized" screens), so they are hidden until a
 * factory reset blanks the device again. Evaluated on every menu cycle,
 * so provisioning / wiping takes effect the moment the menu returns. */
static int menu_build_visible(int *vis, int max)
{
	bool initd = false;
	const se_driver_t *se = se_active();
	if (se && se->is_initialized)
		se->is_initialized(&initd);
	int n = 0;
	for (int i = 0; i < MENU_COUNT && n < max; i++) {
		if (initd && (i == 0 || i == 1))   /* INITIALIZE / RECOVER */
			continue;
		if (i == 4 && !os_fido_is_active()) /* FIDO app deleted */
			continue;
		vis[n++] = i;
	}
	return n;
}

#define ARROW_Y0  230
#define ARROW_Y1  290
/* three-button nav: LEFT | OK | RIGHT */
#define ARROW_X0  15
#define ARROW_X1  80
#define OK_X0     90
#define OK_X1     150
#define RARROW_X0 160
#define RARROW_X1 225
/* selection box framing the single visible menu item. Only the box (or
 * the OK key) activates the item — taps outside do nothing. Full panel
 * width: the widest label ("FACTORY RESET", 232px at 2x) must fit. */
#define ITEM_X0   0
#define ITEM_Y0   134
#define ITEM_X1   240
#define ITEM_Y1   186

/* Draw `s` centered horizontally with 8x16 glyphs at 2x scale (16x32px
 * per char), on `bg`. Used for the single visible menu item inside its
 * selection box. */
/* Draw a menu item centered horizontally with 8x16 (ASCII) / 16x16 (CJK)
 * glyphs at 2x scale (32px tall), on `bg`. Used for the single visible
 * menu item inside its selection box. */
static void menu_draw_item(const char *s, int y, uint16_t fg, uint16_t bg)
{
	int scale = 2;
	int tw = lcd_utf8_width(s, scale);
	int x = (240 - tw) / 2;
	if (x < 0) x = 0;
	lcd_utf8_str(x, y, s, fg, bg, scale);
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

static void menu_draw(const int *vis, int vn)
{
	(void)vn;
	lcd_fill(C_BG);
	/* header hints at 2x: the old 5x7 lines were too small to read */
	lcd_line_big(2, 6, "HardID", C_LBL, C_BG);
	lcd_line_big(2, 26, "OK: open", C_DIM, C_BG);

	/* the item sits in a filled selection box so it is obvious what a
	 * tap/OK will activate (and that tapping outside does nothing) */
	draw_round_rect(ITEM_X0, ITEM_Y0, ITEM_X1, ITEM_Y1, 10, C_BTN);
	menu_draw_item(os_lang_str(s_menu_keys[vis[s_sel]]), 140, C_FG, C_BTN);

	draw_arrow(ARROW_X0, ARROW_Y0, ARROW_X1, ARROW_Y1, -1);
	/* center OK key confirms the selection */
	draw_round_rect(OK_X0, ARROW_Y0, OK_X1, ARROW_Y1, 8, C_BTN);
	{
		int tw = 2 * (F8_W + 2) - 2;          /* "OK" at 1x scale */
		int x = (OK_X0 + OK_X1 - tw) / 2;
		int y = (ARROW_Y0 + ARROW_Y1) / 2 - 8;
		lcd_gl8x16(x, y, 'O', C_FG, C_BTN, 1);
		lcd_gl8x16(x + F8_W + 2, y, 'K', C_FG, C_BTN, 1);
	}
	draw_arrow(RARROW_X0, ARROW_Y0, RARROW_X1, ARROW_Y1, 1);
}

static void menu_run_sel(int item)
{
	switch (item) {
	case 0: screen_run_initialize();    break;
	case 1: screen_run_recover();       break;
	case 2: screen_run_sign();          break;
	case 3: screen_run_link_host();     break;
	case 4: screen_run_fido();          break;
	case 5: screen_run_apps(true);      break;
	case 6: screen_run_pin();           break;
	case 7: screen_run_about();         break;
	case 8: screen_run_language();      break;
	case 9: screen_run_factory_reset(); break;
	}
}

/* First-boot PIN gate. If the SE carries no PIN yet (fresh device or after
 * a wipe), offer one (optional) before the menu is reached. The PIN protects
 * the wallet (FIDO has no PIN) and persists across factory resets. */
static void boot_pin_gate(void)
{
	const se_driver_t *se = se_active();

	/* DEV-ONLY: no-PIN builds skip the gate entirely and pre-unlock the
	 * SE session so signing works without any prompt. Real hardware must
	 * keep HARDID_DEV_NO_PIN off (backend's dev_unlock stays NULL). */
	if (os_dev_no_pin_enabled()) {
		if (se->dev_unlock)
			se->dev_unlock();
		return;
	}

	bool pin_set = false;
	if (se->is_pin_set && se->is_pin_set(&pin_set) == SE_OK && pin_set)
		return;
	/* No PIN: offer one (optional). The wallet can run PIN-less; the user
	 * may set/change it any time from the PIN menu. */
	if (ui_confirm("Set a PIN to protect the wallet?")) {
		char pin[OS_PIN_MAX_LEN + 1];
		int len = ui_set_pin(pin, (int)sizeof(pin));
		if (len >= 0) {
			se->set_pin((const uint8_t *)pin, (size_t)len);
			os_secure_bzero(pin, sizeof(pin));
		}
	}
}

/* True when the SE carries a PIN (else the wallet runs unlocked). */
static bool wallet_has_pin(void)
{
	const se_driver_t *se = se_active();
	bool set = false;
	if (se && se->is_pin_set)
		se->is_pin_set(&set);
	return set;
}

/* Ask for the wallet PIN and block until verified (unlocks the SE). */
static void wallet_unlock_gate(void)
{
	const se_driver_t *se = se_active();
	for (;;) {
		lcd_fill(C_BG);
		lcd_line(2, 2, "Wallet locked", C_LBL, C_BG);
		char pin[OS_PIN_MAX_LEN + 1];
		int n = ui_enter_pin(pin, sizeof(pin));
		if (n < 0)
			continue;   /* cancelled → stay on the lock screen */
		uint32_t wait;
		bool duress;
		int vr = se->verify_pin((const uint8_t *)pin, (size_t)n, &wait, &duress);
		os_secure_bzero(pin, sizeof(pin));
		if (vr == SE_OK)
			return;
		lcd_fill(C_BG);
		lcd_text_wrap(2, 40, "Wrong PIN.", C_ERR, C_BG);
		ui_wait_ack();
	}
}

void ui_run(void)
{
	screen_run_splash();
	boot_pin_gate();

	/* PIN gate BEFORE the brain-phrase gate: the wallet PIN is asked for
	 * first (a PIN-less wallet skips it), then the passphrase. */
	if (wallet_has_pin()) {
		bool unlocked = false;
		const se_driver_t *se = se_active();
		if (se && se->is_unlocked)
			se->is_unlocked(&unlocked);
		if (!unlocked)
			wallet_unlock_gate();
	}

	screen_boot_passphrase_gate();

	for (;;) {
		/* Dynamic unlock check: a PIN that was just (re)set locks the SE
		 * again (set_pin clears unlocked), so we re-query each loop instead
		 * of caching a flag — setting a PIN must require re-entry. */
		bool unlocked = true;
		if (wallet_has_pin()) {
			const se_driver_t *se = se_active();
			if (se && se->is_unlocked)
				se->is_unlocked(&unlocked);
		}
		if (!unlocked) {
			wallet_unlock_gate();
			continue;
		}

		/* Read the auto-lock timeout every pass so a change made in the
		 * PIN menu takes effect immediately (no stale cached value). */
		uint32_t lock_ms = 0;
		{
			const se_driver_t *se = se_active();
			uint32_t sec = 0;
			if (se && se->get_lock_timeout)
				se->get_lock_timeout(&sec);
			lock_ms = sec * 1000u;
		}

		int vis[MENU_COUNT];
		int vn = menu_build_visible(vis, MENU_COUNT);
		if (s_sel >= vn)
			s_sel = 0;
		menu_draw(vis, vn);
		int px, py;
		if (!ui_wait_press_to(&px, &py, lock_ms)) {
			/* idle timeout: auto-lock the wallet (FIDO stays PIN-less) */
			const se_driver_t *se = se_active();
			if (se && se->lock)
				se->lock();
			continue;
		}
		int rx = px, ry = py;
		ui_wait_release(&rx, &ry);
		if (!(ui_pt_in(rx, ry, px - 20, py - 20, px + 20, py + 20) ||
		      (rx == px && ry == py)))
			continue;
		if (ui_pt_in(px, py, ARROW_X0, ARROW_Y0, ARROW_X1, ARROW_Y1)) {
			s_sel = (s_sel + vn - 1) % vn;
		} else if (ui_pt_in(px, py, RARROW_X0, ARROW_Y0, RARROW_X1, ARROW_Y1)) {
			s_sel = (s_sel + 1) % vn;
		} else if (ui_pt_in(px, py, OK_X0, ARROW_Y0, OK_X1, ARROW_Y1)) {
			menu_run_sel(vis[s_sel]);    /* OK key confirms */
		} else if (ui_pt_in(px, py, ITEM_X0, ITEM_Y0, ITEM_X1, ITEM_Y1)) {
			menu_run_sel(vis[s_sel]);    /* tapping the selection box = confirm */
		}
		/* any other tap is ignored — no accidental activation */
	}
}
