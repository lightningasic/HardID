/*
 * HardID Hardware Wallet — App catalog (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The device has no network, so installable apps cannot be fetched from a
 * server. Instead the firmware carries a built-in CATALOG of officially
 * reviewed apps. "Installing" an app activates a catalog entry into the
 * registry; "deleting" uninstalls it. Core apps (BTC/ETH) are pre-installed
 * and cannot be removed; catalog apps are optional (selectable).
 *
 * Every catalog parse() is a FIRMWARE clean-room parser (EVM RLP or BTC
 * PSBT) — the same code signsvc independently re-derives with, so WYSIWYS
 * holds for catalog apps exactly as for core apps. A third-party .hdapp
 * push flow (link_esp) can coexist but is separate.
 */

#ifndef HARDID_APP_CATALOG_H
#define HARDID_APP_CATALOG_H

#include <stddef.h>
#include "app.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Number of entries in the built-in optional-app catalog. */
size_t os_app_catalog_count(void);

/* Fetch a catalog entry by index (0 .. count-1). NULL out of range. */
const os_app *os_app_catalog_at(size_t index);

/* Look up a catalog entry by app_id. NULL if not in the catalog. */
const os_app *os_app_catalog_by_id(const char *app_id);

/* Install a catalog entry into the registry (activate it). Returns 0 on
 * success, -1 if the id is not in the catalog, already installed, the
 * registry is full, or its id/coin collides with an existing app. */
int os_app_catalog_install(const char *app_id);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_APP_CATALOG_H */
