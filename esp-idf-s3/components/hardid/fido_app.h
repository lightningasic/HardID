/*
 * HardID — FIDO as a removable preinstalled app
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * FIDO is preinstalled and ACTIVE by default (boots straight into FIDO
 * serving). The user can delete it (wipe its credentials + boot into the
 * wallet menu on next power-on) or activate it again from the APP MARKET.
 * The FIDO "installer" is the firmware itself, kept on device, so deletion
 * never needs a host — re-activating just flips the persisted flag back on.
 */

#ifndef HARDID_FIDO_APP_H
#define HARDID_FIDO_APP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Is the FIDO app active (boot into FIDO serving)? Persisted in NVS,
 * defaults to true (preinstalled). */
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