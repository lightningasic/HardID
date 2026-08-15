/*
 * HardID — FIDO as a removable preinstalled app
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * FIDO is bundled with the firmware but NOT installed by default (factory
 * state: the wallet boots into its menu; the user opts in via APP MARKET).
 * The user can delete it (wipe its credentials + boot into the wallet
 * menu on next power-on) or activate it again from the APP MARKET. The
 * FIDO "installer" is the firmware itself, kept on device, so deletion
 * never needs a host — re-activating just flips the persisted flag back on.
 * Even when installed, FIDO only serves once the wallet is initialized
 * (FIDO keys derive from the wallet seed). */

#ifndef HARDID_FIDO_APP_H
#define HARDID_FIDO_APP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pure installed flag (factory default: bundled, not installed). Used for
 * display; the boot path uses os_fido_is_active(). */
bool os_fido_installed(void);

/* Is FIDO serving? True only when the app is installed AND the wallet is
 * initialized (FIDO keys derive from the wallet seed). Persisted in NVS,
 * defaults to false (not installed). */
bool os_fido_is_active(void);

/* Persist the active flag. Takes effect at next power-on (boot path reads
 * it in ui_task). */
void os_fido_set_active(bool on);

/* Delete every registered FIDO credential (advance the SE FIDO epoch).
 * Wallet seed/PIN are untouched. */
void os_fido_wipe_credentials(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_FIDO_APP_H */