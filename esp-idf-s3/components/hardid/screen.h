/*
 * HardID — device screen flows (initialize / sign / factory reset)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Layer 2 (logic): the three Trezor-style workflows. Each takes over the
 * whole display, drives the keypad for PIN/confirm, and returns when the
 * screen should hand control back to the main menu. This layer knows the
 * SE backend (se_driver) but is independent of how input is captured.
 */

#ifndef HARDID_SCREEN_H
#define HARDID_SCREEN_H

#include "app.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Software/firmware version, shown in the ABOUT screen. */
#define HARDID_FW_VERSION "0.2.0"

/* Initialize: if not yet provisioned, generate a seed, show + confirm the
 * recovery phrase, set a PIN, and store the seed in the SE. */
void screen_run_initialize(void);

/* Sign: refuse unless provisioned, unlock with PIN, sign the fixed test
 * digest and show the r||s hex, wait for a tap to return. */
void screen_run_sign(void);

/* Sign with a specific app (V2.0): unlock with PIN then run the
 * sign-delegation flow for `app`. */
void screen_run_sign_for_app(const os_app *app);

/* WYSIWYS confirm hook shared by the on-device SIGN flow and HOST LINK:
 * renders a parsed intent and requires an explicit user confirm. Returns
 * true only on confirmation. */
bool screen_confirm_intent(const os_tx_intent *it);

/* Factory reset: confirm dialog, wipe the SE, return to home. */
void screen_run_factory_reset(void);

/* Recover: on a wiped device, type the existing BIP39 mnemonic on the
 * on-screen keypad, validate its checksum, re-derive the seed, set a new
 * PIN and store it. Input is masked as it is typed. */
void screen_run_recover(void);

/* Host link: PIN-unlock then serve framed requests (status/sign) over the
 * USB-Serial-JTAG port. See link_esp.c. Returns on tap. */
void screen_run_link_host(void);

/* FIDO (F3 transport): PIN-unlock (A6) then serve CTAPHID frames over the
 * TinyUSB HID interface (usb_desc.c / fido_esp.c). Per-request confirm
 * screen is F5. Returns on tap. */
void screen_run_fido(void);

/* About: show hardware and firmware version, tap to return. */
void screen_run_about(void);

/* PIN setup/change: set a PIN if none is set, or (after verifying the
 * current PIN) set a new one. PIN protects the wallet only — FIDO has no
 * PIN. Returns on back. */
void screen_run_pin(void);

/* Language selection (English / 中文 / 日本語 / 한국어). Persists the
 * choice and re-renders the menu on return. Returns on select/back. */
void screen_run_language(void);

/* Boot splash: draw the HardID logo bitmap with the wordmark below it. */
void screen_run_splash(void);

/* Boot-time passphrase gate (TREZOR model): asked on every power-on of an
 * initialized device; folds the entered passphrase into a volatile session
 * seed. A blank/wiped device skips. See screen.c. */
void screen_boot_passphrase_gate(void);

/* App market (V2.0): list installed apps (core + runtime), show their
 * state/version, and let the user select one to sign with. `manage` adds
 * the removable preinstalled FIDO app row (delete/activate) — used by the
 * main-menu APP MARKET; SIGN's picker passes false so FIDO (not a signing
 * app) never appears there. Returns on tap/back. */
void screen_run_apps(bool manage);

/* FIDO app manager: delete (wipe credentials, boot into wallet next power
 * cycle) or re-activate (boot into FIDO serving again) the removable
 * preinstalled FIDO app. Returns on back. */
void screen_fido_manage(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SCREEN_H */