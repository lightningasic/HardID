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

static int btc_parse(const uint8_t *tx, size_t len, os_tx_intent *o)
{
	os_psbt_summary s;

	/* No change-check callback here: the caller (signsvc) can pass one
	 * through if it can derive addresses; keep it simple + strict. */
	if (os_psbt_parse(tx, len, NULL, &s) != 0)
		return -1;

	memset(o, 0, sizeof(*o));
	o->chain = OS_CHAIN_BTC;
	o->kind = OS_INTENT_TRANSFER;
	o->risk = OS_RISK_LOW;
	o->fee_limit = s.fee;

	/* Surface the first non-change output as "to"; sum the rest. */
	if (s.spend_count == 0 && s.output_count > 0) {
		/* only change outputs — treat as low-risk self-send */
		snprintf(o->to, sizeof(o->to), "self (change only)");
		o->amount = s.total_out;
	} else if (s.spend_count > 0) {
		snprintf(o->to, sizeof(o->to), "%.47s", s.outputs[0].address);
		o->amount = s.outputs[0].amount;
		o->risk = (s.spend_count > 1) ? OS_RISK_MEDIUM : OS_RISK_LOW;
	} else {
		snprintf(o->to, sizeof(o->to), "N/A");
	}
	snprintf(o->amount_token, sizeof(o->amount_token), "sats");
	snprintf(o->symbol, sizeof(o->symbol), "BTC");
	return 0;
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

static int eth_parse(const uint8_t *tx, size_t len, os_tx_intent *o)
{
	return os_clearsign_parse_evm(tx, len, o);
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
#define OS_APP_MAX_INSTALLED 16

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
	if (os_app_by_id(desc->app_id) != NULL)
		return -1;                       /* id already taken (core or installed) */
	if (os_app_by_coin(desc->coin_type) != NULL)
		return -1;                       /* coin_type already claimed */
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
