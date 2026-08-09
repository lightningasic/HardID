/*
 * HardID Hardware Wallet — App abstraction (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * V2.0 architecture: a single master private key (BIP32 root seed) derives
 * every coin's keys, and each coin/protocol that needs signing is a separate
 * App. An App is a *parser plugin*: it turns a raw transaction into a
 * human-readable intent (parsed_intent). The App NEVER holds key material —
 * signing is delegated to the system firmware (signsvc), which renders the
 * intent, requires user confirmation, then signs inside the SE.
 *
 * Apps live in a registry (app_registry.h). Core apps (BTC, ETH) are built
 * in; third-party apps are installed at runtime after official review
 * (official-signature verification + reproducible build hash). This header
 * defines the App descriptor and the parser contract.
 */

#ifndef HARDID_APP_H
#define HARDID_APP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "clearsign.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound on runtime-installed (non-core) apps. Shared by the registry
 * and by the on-device install UI. */
#define OS_APP_MAX_INSTALLED 16

/* App state on the device. */
typedef enum {
	OS_APP_CORE,      /* built-in core app (BTC/ETH), cannot be uninstalled */
	OS_APP_INSTALLED, /* third-party app, officially signed + installed */
	OS_APP_SUSPENDED, /* revoked — must not serve sign requests */
} os_app_state;

typedef struct {
	char     app_id[16];        /* "btc", "eth", "usdt", ... */
	char     name[24];          /* display name */
	uint32_t coin_type;         /* BIP44 coin' (0=BTC, 60=ETH, ...) */
	uint32_t version;           /* monotonically increasing, anti-rollback */
	os_app_state state;
	bool     is_core;

	/* Parse a raw transaction into a Clear Sign intent. coin_type is the
	 * app's own BIP44 coin' (passed by the caller so a SHARED parser —
	 * e.g. the BTC-family PSBT parser used by LTC/DOGE/BCH catalog apps —
	 * can render per-coin address encodings). Returns 0 on success, -1 on
	 * malformed input (caller degrades to UNKNOWN + data hash). */
	int (*parse)(const uint8_t *tx, size_t len, uint32_t coin_type,
	             os_tx_intent *out);
} os_app;

/* Look up an App by id. Returns NULL if not present/not installed. */
const os_app *os_app_by_id(const char *app_id);

/* Look up an App by BIP44 coin_type. */
const os_app *os_app_by_coin(uint32_t coin_type);

/* Iterate installed apps. Returns index, or NULL at end.
 *   const os_app *a;
 *   size_t i = 0;
 *   while ((a = os_app_at(i++)) != NULL) { ... }
 */
const os_app *os_app_at(size_t index);

/* Total number of present apps (core + installed). */
size_t os_app_count(void);

/* ---- install/uninstall (firmware-only; called by the app manager after
 * official-signature + build-hash verification) ---- */

/* Register a runtime-installed app. `desc` is copied. The caller owns the
 * parse function's lifetime (it must be a firmware-resident or sandboxed
 * trampoline). Returns 0 on success, -1 if the id/coin_type conflicts or
 * the registry is full. */
int os_app_register(const os_app *desc);

/* Suspend a runtime app (revocation). state → OS_APP_SUSPENDED and sign
 * delegation refuses it. Returns 0 on success, -1 if not installed. */
int os_app_suspend(const char *app_id);

/* Remove a runtime app. Returns 0 on success, -1 if not installed / core. */
int os_app_uninstall(const char *app_id);

/* Bump the installed-app version if > current (anti-rollback). */
int os_app_bump_version(const char *app_id, uint32_t version);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_APP_H */
