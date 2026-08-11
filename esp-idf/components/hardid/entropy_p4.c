/*
 * HardID Hardware Wallet — ESP32-P4 physical entropy collector (Layer A)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * P4 twin of entropy_s3.c. Same Layer A sources (docs/08_HardID_多熵源设计.md):
 * touch jitter (S4), temperature-sensor noise (S5), I2C bus timing jitter
 * (S6). The RTC drift source (S7) uses esp_timer LSB jitter here — the P4
 * exposes no RTC counter register like the S3's RTC_CNTL_TIME.
 *
 * Never fails closed: unavailable sources are skipped; if none contribute,
 * os_seed_phys_extra returns 1 and seed generation proceeds from the core
 * SE+MCU+host sources.
 */

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "driver/temperature_sensor.h"

#include "seed.h"
#include "phys_entropy.h"
#include "touch.h"

static const char *TAG = "hardid.entropy";

/* Force the linker to pull this object into the image — os_seed_phys_extra
 * is the only symbol this file exports, and seed.c's weak default would
 * otherwise satisfy the reference from seed.c.obj, leaving the weak no-op
 * hook in the image. Referenced from board_p4.c. */
void os_entropy_force_link(void)
{
}

#define TOUCH_COLLECT_MS   150
#define TOUCH_SAMPLES_MAX  64
#define TSENS_SAMPLES      8
#define BUS_ROUNDS         8

static void absorb_u32(os_phys_pool_t *pool, uint32_t v)
{
	uint8_t b[4];
	b[0] = (uint8_t)(v & 0xff);
	b[1] = (uint8_t)((v >> 8) & 0xff);
	b[2] = (uint8_t)((v >> 16) & 0xff);
	b[3] = (uint8_t)((v >> 24) & 0xff);
	os_phys_pool_absorb(pool, b, sizeof b);
}

static int collect_touch(os_phys_pool_t *pool)
{
	int n = 0;
	int start = (int)(esp_timer_get_time() / 1000);

	while (n < TOUCH_SAMPLES_MAX) {
		int x, y;
		if (!touch_get(&x, &y))
			break;
		absorb_u32(pool, (uint32_t)((x & 0x0f) | ((y & 0x0f) << 4)));
		n++;
		vTaskDelay(pdMS_TO_TICKS(2));
		if ((int)(esp_timer_get_time() / 1000) - start > TOUCH_COLLECT_MS)
			break;
	}
	if (n > 0)
		ESP_LOGD(TAG, "touch jitter samples=%d", n);
	return n > 0;
}

static int collect_tsens(os_phys_pool_t *pool)
{
	temperature_sensor_config_t cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
	temperature_sensor_handle_t tsens = NULL;
	int n = 0;

	if (temperature_sensor_install(&cfg, &tsens) != ESP_OK)
		return 0;
	if (temperature_sensor_enable(tsens) != ESP_OK) {
		temperature_sensor_uninstall(tsens);
		return 0;
	}
	for (int i = 0; i < TSENS_SAMPLES; i++) {
		float c;
		if (temperature_sensor_get_celsius(tsens, &c) == ESP_OK) {
			uint32_t bits;
			memcpy(&bits, &c, sizeof bits);
			absorb_u32(pool, bits);
			n++;
		}
	}
	temperature_sensor_disable(tsens);
	temperature_sensor_uninstall(tsens);
	return n > 0;
}

static int collect_bus(os_phys_pool_t *pool)
{
	int n = 0;
	int x, y;

	for (int i = 0; i < BUS_ROUNDS; i++) {
		int64_t t0 = esp_timer_get_time();
		if (!touch_get(&x, &y))
			continue;
		int64_t dt = esp_timer_get_time() - t0;
		absorb_u32(pool, (uint32_t)dt);
		n++;
	}
	return n > 0;
}

/* S7: esp_timer LSB jitter (P4 has no RTC counter register). */
static int collect_rtc(os_phys_pool_t *pool)
{
	absorb_u32(pool, (uint32_t)esp_timer_get_time());
	return 1;
}

int os_seed_phys_extra(uint8_t *buf, size_t len)
{
	os_phys_pool_t pool;

	if (!buf || len == 0)
		return 1;

	os_phys_pool_init(&pool);

	collect_touch(&pool);
	collect_tsens(&pool);
	collect_bus(&pool);
	collect_rtc(&pool);

	os_phys_pool_extract(&pool, buf, len);
	ESP_LOGI(TAG, "physical entropy mixed into seed");
	return 0;
}
