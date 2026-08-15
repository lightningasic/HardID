/*
 * HardID — FIDO as a removable preinstalled app (persistence)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * The FIDO app's active flag lives in its own NVS namespace ("fido_app"),
 * separate from the mock-SE namespace, so it can be toggled without
 * touching wallet state. Defaults to active (preinstalled app).
 */

#include "fido_app.h"

#include "nvs.h"
#include "nvs_flash.h"
#include "se_driver.h"

#define FIDO_APP_NVS_NS "fido_app"

bool os_fido_is_active(void)
{
	bool active = true;   /* preinstalled + active by default */
	nvs_flash_init();
	nvs_handle_t h;
	if (nvs_open(FIDO_APP_NVS_NS, NVS_READONLY, &h) != ESP_OK)
		return active;
	uint8_t v = 1;
	if (nvs_get_u8(h, "active", &v) != ESP_OK)
		v = 1;
	active = v != 0;
	nvs_close(h);
	return active;
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