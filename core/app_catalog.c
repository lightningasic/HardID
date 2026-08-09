/*
 * HardID Hardware Wallet — App catalog (V2.0)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include <string.h>

#include "app_catalog.h"
#include "clearsign.h"

/* Built-in, officially reviewed optional apps. Each coin_type is unique
 * (the registry enforces it) and each parse() is a firmware clean-room
 * parser, so a catalog app is verified by signsvc exactly like a core app.
 *
 * BTC-like chains reuse the PSBT parser; EVM chains reuse the EVM parser.
 * Extend this table to grow the reviewable market. */
static const os_app s_catalog[] = {
	{
		.app_id = "ltc", .name = "Litecoin", .coin_type = 2,
		.version = 1, .state = OS_APP_INSTALLED, .is_core = false,
		.parse = os_clearsign_parse_btc,
	},
	{
		.app_id = "doge", .name = "Dogecoin", .coin_type = 3,
		.version = 1, .state = OS_APP_INSTALLED, .is_core = false,
		.parse = os_clearsign_parse_btc,
	},
	{
		.app_id = "bch", .name = "Bitcoin Cash", .coin_type = 145,
		.version = 1, .state = OS_APP_INSTALLED, .is_core = false,
		.parse = os_clearsign_parse_btc,
	},
	{
		.app_id = "etc", .name = "Ethereum Classic", .coin_type = 61,
		.version = 1, .state = OS_APP_INSTALLED, .is_core = false,
		.parse = os_clearsign_parse_evm,
	},
	{
		.app_id = "polygon", .name = "Polygon", .coin_type = 966,
		.version = 1, .state = OS_APP_INSTALLED, .is_core = false,
		.parse = os_clearsign_parse_evm,
	},
};

size_t os_app_catalog_count(void)
{
	return sizeof(s_catalog) / sizeof(s_catalog[0]);
}

const os_app *os_app_catalog_at(size_t index)
{
	if (index >= os_app_catalog_count())
		return NULL;
	return &s_catalog[index];
}

const os_app *os_app_catalog_by_id(const char *app_id)
{
	if (!app_id)
		return NULL;
	for (size_t i = 0; i < os_app_catalog_count(); i++)
		if (strcmp(s_catalog[i].app_id, app_id) == 0)
			return &s_catalog[i];
	return NULL;
}

int os_app_catalog_install(const char *app_id)
{
	const os_app *e = os_app_catalog_by_id(app_id);
	if (!e)
		return -1;
	return os_app_register(e);
}
