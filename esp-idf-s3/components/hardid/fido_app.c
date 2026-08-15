/*
 * HardID — FIDO as a removable preinstalled app (persistence)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The FIDO app's installed flag lives in its own NVS namespace ("fido_app"),
 * separate from the mock-SE namespace, so it can be toggled without
 * touching wallet state. Factory default: bundled but NOT installed — the
 * user opts in via APP MARKET. Even when installed, FIDO only serves once
 * the wallet is initialized: FIDO private keys are derived from the wallet
 * seed (se_mock.c mock_fido_priv), so no seed = no PK = FIDO must not work.
 */

#include "fido_app.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "se_driver.h"

#define FIDO_APP_NVS_NS "fido_app"

/* Pure installed flag (factory default: bundled, not installed). */
bool os_fido_installed(void)
{
	nvs_flash_init();
	nvs_handle_t h;
	if (nvs_open(FIDO_APP_NVS_NS, NVS_READONLY, &h) != ESP_OK)
		return false;
	uint8_t v = 0;
	if (nvs_get_u8(h, "active", &v) != ESP_OK)
		v = 0;
	nvs_close(h);
	return v != 0;
}

/* Installed AND the wallet is initialized. FIDO private keys derive from
 * the wallet seed, so with no seed there is no PK and FIDO must not serve
 * — this is what the boot path checks. */
bool os_fido_is_active(void)
{
	if (!os_fido_installed())
		return false;
	const se_driver_t *se = se_active();
	bool initd = false;
	if (se && se->is_initialized)
		se->is_initialized(&initd);
	return initd;
}

void os_fido_set_active(bool on)
{
	nvs_flash_init();
	nvs_handle_t h;
	if (nvs_open(FIDO_APP_NVS_NS, NVS_READWRITE, &h) != ESP_OK)
		return;
	nvs_set_u8(h, "active", on ? 1 : 0);
	nvs_commit(h);
	nvs_close(h);
}

void os_fido_wipe_credentials(void)
{
	const se_driver_t *se = se_active();
	if (se && se->fido_wipe)
		se->fido_wipe();
}