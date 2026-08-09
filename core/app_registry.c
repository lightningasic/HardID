/*
 * HardID Hardware Wallet — App registry (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Core apps (BTC, ETH) are compiled in. Third-party apps register at
 * runtime (install flow verifies official signature + build hash before
 * calling os_app_register). The registry is read-only to Apps themselves;
 * only firmware install/uninstall paths mutate it.
 */

#include <string.h>
#include <stdio.h>

#include "app.h"
#include "psbt.h"
#include "clearsign.h"
#include "secp256k1.h"

/* ---- core app: BTC (PSBT) ---- */

static int btc_parse(const uint8_t *tx, size_t len, uint32_t coin_type,
                     os_tx_intent *o)
{
	/* Core BTC app delegates to the FIRMWARE clean-room parser. signsvc
	 * independently re-checks with the same firmware implementation, so a
	 * (hypothetical) bug in this app cannot be the sole source of truth. */
	return os_clearsign_parse_btc_coin(tx, len, coin_type, o);
}

static const os_app app_btc = {
	.app_id = "btc",
	.name = "Bitcoin",
	.coin_type = 0,
	.version = 1,
	.state = OS_APP_CORE,
	.is_core = true,
	.parse = btc_parse,
};

/* ---- core app: ETH (EVM RLP / EIP-1559) ---- */

static int eth_parse(const uint8_t *tx, size_t len, uint32_t coin_type,
                     os_tx_intent *o)
{
	return os_clearsign_parse_evm_coin(tx, len, coin_type, o);
}

static const os_app app_eth = {
	.app_id = "eth",
	.name = "Ethereum",
	.coin_type = 60,
	.version = 1,
	.state = OS_APP_CORE,
	.is_core = true,
	.parse = eth_parse,
};

/* ---- registry ---- */

#define OS_APP_CORE_COUNT 2

static const os_app *s_core[OS_APP_CORE_COUNT] = { &app_btc, &app_eth };

/* Runtime-installed apps (third-party). Bounded. */
static os_app s_installed[OS_APP_MAX_INSTALLED];
static size_t s_installed_count;

const os_app *os_app_by_id(const char *app_id)
{
	if (!app_id)
		return NULL;
	for (size_t i = 0; i < OS_APP_CORE_COUNT; i++) {
		if (strcmp(s_core[i]->app_id, app_id) == 0)
			return s_core[i];
	}
	for (size_t i = 0; i < s_installed_count; i++) {
		if (strcmp(s_installed[i].app_id, app_id) == 0 &&
		    s_installed[i].state != OS_APP_SUSPENDED)
			return &s_installed[i];
	}
	return NULL;
}

const os_app *os_app_by_coin(uint32_t coin_type)
{
	for (size_t i = 0; i < OS_APP_CORE_COUNT; i++) {
		if (s_core[i]->coin_type == coin_type)
			return s_core[i];
	}
	for (size_t i = 0; i < s_installed_count; i++) {
		if (s_installed[i].coin_type == coin_type &&
		    s_installed[i].state != OS_APP_SUSPENDED)
			return &s_installed[i];
	}
	return NULL;
}

const os_app *os_app_at(size_t index)
{
	size_t i = index;
	if (i < OS_APP_CORE_COUNT)
		return s_core[i];
	i -= OS_APP_CORE_COUNT;
	if (i < s_installed_count)
		return &s_installed[i];
	return NULL;
}

size_t os_app_count(void)
{
	return OS_APP_CORE_COUNT + s_installed_count;
}

static os_app *find_installed(const char *app_id)
{
	if (!app_id)
		return NULL;
	for (size_t i = 0; i < s_installed_count; i++) {
		if (strcmp(s_installed[i].app_id, app_id) == 0)
			return &s_installed[i];
	}
	return NULL;
}

int os_app_register(const os_app *desc)
{
	if (!desc || !desc->app_id[0] || !desc->parse)
		return -1;
	/* app_id and name MUST be NUL-terminated inside their fixed buffers,
	 * otherwise find_installed's strcmp would read out of bounds. */
	if (memchr(desc->app_id, '\0', sizeof(desc->app_id)) == NULL)
		return -1;
	if (memchr(desc->name, '\0', sizeof(desc->name)) == NULL)
		return -1;
	/* id must be unique across core + installed + suspended entries —
	 * otherwise a revoked app could be re-registered under the same id
	 * and shadow a still-suspended slot (state inconsistency). A core id
	 * is likewise rejected so the market view never shows two entries
	 * sharing one id. */
	if (find_installed(desc->app_id) != NULL)
		return -1;
	if (os_app_by_id(desc->app_id) != NULL)
		return -1;                       /* collides with a core app id */
	if (os_app_by_coin(desc->coin_type) != NULL)
		return -1;                       /* coin_type already claimed (core/active) */
	/* a SUSPENDED app must also keep its coin_type — otherwise a revoked
	 * malicious app could be replaced by a new app claiming the same BIP44
	 * coin branch, inheriting the trust users placed in that coin. Scan
	 * installed slots INCLUDING suspended ones (os_app_by_coin skips them). */
	for (size_t i = 0; i < s_installed_count; i++)
		if (s_installed[i].coin_type == desc->coin_type)
			return -1;
	if (s_installed_count >= OS_APP_MAX_INSTALLED)
		return -1;

	os_app *slot = &s_installed[s_installed_count++];
	memcpy(slot, desc, sizeof(*slot));
	slot->state = OS_APP_INSTALLED;
	slot->is_core = false;
	return 0;
}

int os_app_suspend(const char *app_id)
{
	os_app *a = find_installed(app_id);
	if (!a)
		return -1;
	a->state = OS_APP_SUSPENDED;
	return 0;
}

int os_app_uninstall(const char *app_id)
{
	os_app *a = find_installed(app_id);
	if (!a || a->is_core)
		return -1;
	/* shift tail down */
	size_t idx = (size_t)(a - s_installed);
	for (size_t i = idx + 1; i < s_installed_count; i++)
		s_installed[i - 1] = s_installed[i];
	s_installed_count--;
	return 0;
}

int os_app_bump_version(const char *app_id, uint32_t version)
{
	os_app *a = find_installed(app_id);
	if (!a)
		return -1;
	if (version <= a->version)
		return -1;                       /* anti-rollback */
	a->version = version;
	return 0;
}
