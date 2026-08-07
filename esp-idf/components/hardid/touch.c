/*
 * HardID — CST816D capacitive touch driver (ESP32-S3-Touch-LCD-2)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * CST816D: I2C address 0x15, touch data from register 0x01:
 *   [0]=gesture, [1]=touch point number, [2]=X high, [3]=X low,
 *   [4]=Y high, [5]=Y low.
 *
 * This board routes only SDA/SCL to the touch chip (no INT, no RST),
 * so the chip is polled. The CST816D only answers I2C while a finger
 * is down; an idle poll therefore returns a NACK/timeout, which the
 * caller treats as "no touch". We use the legacy synchronous I2C
 * driver (no async queue) because the async engine is unstable when
 * polled in a tight loop.
 */

#include <string.h>
#include "driver/i2c.h"
#include "esp_log.h"
#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "touch.h"
#include "board_p4.h"

#define TOUCH_I2C_PORT       I2C_NUM_0
#define TOUCH_I2C_ADDR       0x15
#define TOUCH_I2C_FREQ       400000

#define LCD_W 240
#define LCD_H 320

static const char *TAG = "hardid.touch";

int touch_init(void)
{
	i2c_config_t cfg = {
		.mode = I2C_MODE_MASTER,
		.sda_io_num = PIN_TOUCH_SDA,
		.scl_io_num = PIN_TOUCH_SCL,
		.sda_pullup_en = GPIO_PULLUP_ENABLE,
		.scl_pullup_en = GPIO_PULLUP_ENABLE,
		.master.clk_speed = TOUCH_I2C_FREQ,
	};
	if (i2c_param_config(TOUCH_I2C_PORT, &cfg) != ESP_OK)
		return -1;
	if (i2c_driver_install(TOUCH_I2C_PORT, I2C_MODE_MASTER, 0, 0, 0) != ESP_OK)
		return -1;

	/* probe the chip ID (reg 0xA7): confirms the bus + address are right */
	uint8_t id = 0;
	uint8_t idreg = 0xA7;
	if (i2c_master_write_read_device(TOUCH_I2C_PORT, TOUCH_I2C_ADDR,
	                                &idreg, 1, &id, 1,
	                                pdMS_TO_TICKS(100)) == ESP_OK)
		ESP_LOGI(TAG, "CST816D ready, chip id 0x%02x", id);
	else
		ESP_LOGW(TAG, "chip-id read failed (idle chip NACKs — normal)");

	return 0;
}

static int touch_read_raw(uint8_t *buf, size_t len)
{
	/* Write the data register address (0x01) first, then read the touch
	 * info. A bare read() would start at the chip's default register and
	 * return the wrong bytes. Very short timeout: an idle chip does not
	 * answer, and a failed poll must not stall the menu for long. */
	uint8_t reg = 0x01;
	esp_err_t rc = i2c_master_write_read_device(TOUCH_I2C_PORT, TOUCH_I2C_ADDR,
	                                           &reg, 1, buf, len,
	                                           pdMS_TO_TICKS(20));
	return (rc == ESP_OK) ? 0 : -1;
}

bool touch_get(int *x, int *y)
{
	uint8_t d[6];
	if (touch_read_raw(d, sizeof(d)) != 0)
		return false;

	uint8_t npoints = d[1] & 0x0F;
	if (npoints == 0)
		return false;

	/* CST816 maps directly to the panel: X in 0..240, Y in 0..320. */
	uint16_t rx = ((uint16_t)d[2] & 0x0F) << 8 | d[3];
	uint16_t ry = ((uint16_t)d[4] & 0x0F) << 8 | d[5];

	if (rx > LCD_W) rx = LCD_W;
	if (ry > LCD_H) ry = LCD_H;
	*x = rx;
	*y = ry;
	return true;
}
