/*
 * HardID — CST816D capacitive touch driver (ESP32-S3-Touch-LCD-2)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * CST816D: I2C address 0x15, touch data from register 0x01:
 *   [0]=gesture, [1]=touch point number, [2]=X high, [3]=X low,
 *   [4]=Y high, [5]=Y low.
 * Polled from the main loop; single point is enough for the menu.
 */

#include <string.h>
#include "driver/i2c_master.h"
#include "esp_log.h"
#include "esp_err.h"

#include "touch.h"

#define TOUCH_I2C_PORT       I2C_NUM_0
#define TOUCH_SDA_GPIO       48
#define TOUCH_SCL_GPIO       47
#define TOUCH_I2C_ADDR       0x15
#define TOUCH_I2C_FREQ       400000

#define LCD_W 240
#define LCD_H 320

static const char *TAG = "hardid.touch";

static i2c_master_bus_handle_t   s_bus  = NULL;
static i2c_master_dev_handle_t   s_dev  = NULL;

int touch_init(void)
{
	i2c_master_bus_config_t bus = {
		.i2c_port = TOUCH_I2C_PORT,
		.sda_io_num = TOUCH_SDA_GPIO,
		.scl_io_num = TOUCH_SCL_GPIO,
		.clk_source = I2C_CLK_SRC_DEFAULT,
		.glitch_ignore_cnt = 7,
		.trans_queue_depth = 4,
		.flags.enable_internal_pullup = 1,
	};
	if (i2c_new_master_bus(&bus, &s_bus) != ESP_OK)
		return -1;

	i2c_device_config_t dev = {
		.dev_addr_length = I2C_ADDR_BIT_LEN_7,
		.device_address = TOUCH_I2C_ADDR,
		.scl_speed_hz = TOUCH_I2C_FREQ,
	};
	if (i2c_master_bus_add_device(s_bus, &dev, &s_dev) != ESP_OK)
		return -1;

	ESP_LOGI(TAG, "CST816D ready (addr 0x%02x)", TOUCH_I2C_ADDR);
	return 0;
}

static int touch_read_raw(uint8_t *buf, size_t len)
{
	uint8_t reg = 0x01;
	esp_err_t rc = i2c_master_transmit_receive(s_dev, &reg, 1, buf, len, 100);
	return (rc == ESP_OK) ? 0 : -1;
}

bool touch_get(int *x, int *y)
{
	uint8_t d[6];
	if (!s_dev) return false;
	if (touch_read_raw(d, sizeof(d)) != 0)
		return false;

	uint8_t npoints = d[1] & 0x0F;
	if (npoints == 0)
		return false;

	/* CST816 maps directly to the panel: X in 0..240, Y in 0..320.
	 * Coordinates are raw panel pixels already; just clamp defensively. */
	uint16_t rx = ((uint16_t)d[2] & 0x0F) << 8 | d[3];
	uint16_t ry = ((uint16_t)d[4] & 0x0F) << 8 | d[5];

	if (rx > LCD_W) rx = LCD_W;
	if (ry > LCD_H) ry = LCD_H;
	*x = rx;
	*y = ry;
	return true;
}