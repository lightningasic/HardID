/*
 * HardID Hardware Wallet — ESP32-S3 physical entropy collector (Layer A)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * Implements os_seed_phys_extra() (core/seed.h): folds additional PHYSICAL
 * entropy sources into os_seed_generate()'s HKDF mix. See
 * docs/08_HardID_多熵源设计.md (Layer A — pure firmware, zero BOM):
 *
 *   S4  touch jitter        - CST816D coordinate LSB jitter while the user
 *                             holds a finger on the screen
 *   S5  analog sensor noise - internal temperature sensor LSB jitter
 *                             (thermal noise, independent of MCU TRNG)
 *   S6  bus timing jitter   - I2C touch-chip read latency LSBs
 *   S7  RTC drift           - RTC slow-clock counter LSBs vs esp_timer
 *
 * All sources are absorbed into an unconditional entropy pool so the output
 * is statistically independent of any attacker-predictable input. The hook
 * NEVER fails closed: if every source is unavailable it returns 1 and seed
 * generation proceeds from the core SE+MCU+host sources.
 */

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "soc/rtc_cntl_reg.h"
#include "driver/temperature_sensor.h"

#include "seed.h"
#include "phys_entropy.h"
#include "secure_zero.h"
#include "touch.h"

static const char *TAG = "hardid.entropy";

/* Force the linker to pull this object into the image. os_seed_phys_extra
 * is the ONLY symbol this file exports, and seed.c provides a weak default
 * for it — so GNU ld's archive scan satisfies the reference from seed.c.obj
 * with the weak definition and never extracts entropy_s3.c.obj, leaving the
 * weak (no-op) hook in the final image. Referencing a dummy symbol here from
 * board code guarantees this TU (and its strong os_seed_phys_extra) is
 * always linked. */
void os_entropy_force_link(void)
{
}

/* Bounded collection window — the hook runs inside seed generation and must
 * never stall it, so every source is time-limited. The touch window is sized
 * so TOUCH_SAMPLES_MAX is reachable at the effective ~10ms/tick poll rate
 * (CONFIG_FREERTOS_HZ=100 floors pdMS_TO_TICKS(2) to 1 tick). */
#define TOUCH_COLLECT_MS   900
#define TOUCH_SAMPLES_MAX  64
#define TSENS_SAMPLES      8
#define BUS_ROUNDS         8

/* Absorb the raw low-entropy LSBs of a 32-bit word into the pool. */
static void absorb_u32(os_phys_pool_t *pool, uint32_t v)
{
	uint8_t b[4];
	b[0] = (uint8_t)(v & 0xff);
	b[1] = (uint8_t)((v >> 8) & 0xff);
	b[2] = (uint8_t)((v >> 16) & 0xff);
	b[3] = (uint8_t)((v >> 24) & 0xff);
	os_phys_pool_absorb(pool, b, sizeof b);
}

/* S4: touch coordinate LSB jitter. Returns 1 if any samples were collected. */
static int collect_touch(os_phys_pool_t *pool)
{
	int n = 0, miss = 0;
	int64_t start = esp_timer_get_time();

	while (n < TOUCH_SAMPLES_MAX) {
		int x, y;
		if (touch_get(&x, &y)) {
			miss = 0;
			absorb_u32(pool, (uint32_t)((x & 0x0f) | ((y & 0x0f) << 4)));
			n++;
		} else if (++miss >= 3) {
			break;   /* tolerate transient read glitches, then give up */
		}
		vTaskDelay(pdMS_TO_TICKS(2));
		if (esp_timer_get_time() - start > (int64_t)TOUCH_COLLECT_MS * 1000)
			break;
	}
	if (n > 0)
		ESP_LOGI(TAG, "touch jitter samples=%d", n);
	return n > 0;
}

/* S5: internal temperature sensor LSB jitter (thermal noise). */
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
			absorb_u32(pool, bits);          /* LSBs of the float carry noise */
			n++;
		}
	}
	temperature_sensor_disable(tsens);
	temperature_sensor_uninstall(tsens);
	return n > 0;
}

/* S6: I2C bus timing jitter — measure touch-chip read latency LSBs. The
 * transaction runs (and jitters) whether or not a finger is down. */
static int collect_bus(os_phys_pool_t *pool)
{
	int n = 0;
	int x, y;

	for (int i = 0; i < BUS_ROUNDS; i++) {
		int64_t t0 = esp_timer_get_time();
		(void)touch_get(&x, &y);
		int64_t dt = esp_timer_get_time() - t0;
		absorb_u32(pool, (uint32_t)dt);      /* sub-us LSBs carry jitter */
		n++;
	}
	return n > 0;
}

/* S7: RTC drift — low 16 bits of the RTC slow-clock counter (150 kHz) has
 * sub-readout jitter against the esp_timer timebase. */
static int collect_rtc(os_phys_pool_t *pool)
{
	uint32_t lo = REG_READ(RTC_CNTL_TIME0_REG);
	uint32_t hi = REG_READ(RTC_CNTL_TIME1_REG);
	(void)hi;
	absorb_u32(pool, lo);
	return 1;
}

int os_seed_phys_extra(uint8_t *buf, size_t len)
{
	os_phys_pool_t pool;
	int got = 0;

	if (!buf || len == 0)
		return 1;

	os_phys_pool_init(&pool);

	if (collect_touch(&pool)) got = 1;
	if (collect_tsens(&pool)) got = 1;
	if (collect_bus(&pool))   got = 1;
	if (collect_rtc(&pool))   got = 1;

	if (!got) {
		/* every source unavailable: leave buf zeroed, skip the mix */
		os_secure_bzero(&pool, sizeof pool);
		memset(buf, 0, len);
		return 1;
	}

	os_phys_pool_extract(&pool, buf, len);
	ESP_LOGI(TAG, "physical entropy mixed into seed");
	return 0;
}
