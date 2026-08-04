/*
 * HardID Hardware Wallet — ESP32-P4 I2C transport for ACL16 (alternative)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include "se_transport_esp32_i2c.h"
#include <string.h>

static se_esp32_i2c_config g_cfg;
static se_chip g_cur;

#ifdef ESP_PLATFORM

#include "driver/i2c.h"

static int esp32_i2c_init(void)
{
	i2c_config_t conf = {
		.mode = I2C_MODE_MASTER,
		.sda_io_num = g_cfg.gpio_sda,
		.scl_io_num = g_cfg.gpio_scl,
		.sda_pullup_en = GPIO_PULLUP_ENABLE,
		.scl_pullup_en = GPIO_PULLUP_ENABLE,
		.master.clk_speed = g_cfg.clock_hz,
	};
	if (i2c_param_config((i2c_port_t)g_cfg.i2c_port, &conf) != ESP_OK)
		return SE_T_ERR_IO;
	if (i2c_driver_install((i2c_port_t)g_cfg.i2c_port, conf.mode, 0, 0, 0) != ESP_OK)
		return SE_T_ERR_IO;
	return SE_T_OK;
}

static void esp32_i2c_cs(se_chip chip, bool active)
{
	if (active)
		g_cur = chip;   /* select slave address for the transaction */
}

static void esp32_i2c_reset(se_chip chip)
{
	(void)chip;   /* I2C SEs reset via command, not a GPIO line */
}

static uint8_t cur_addr(void)
{
	return (g_cur == SE_CS_1) ? g_cfg.addr_se1 : g_cfg.addr_se2;
}

static int esp32_i2c_write(const uint8_t *buf, size_t len)
{
	return i2c_master_write_to_device((i2c_port_t)g_cfg.i2c_port, cur_addr(),
	                                  buf, len, pdMS_TO_TICKS(1000)) == ESP_OK
		? SE_T_OK : SE_T_ERR_IO;
}

static int esp32_i2c_read(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
	esp_err_t e = i2c_master_read_from_device((i2c_port_t)g_cfg.i2c_port,
	                                          cur_addr(), buf, len,
	                                          pdMS_TO_TICKS(timeout_ms));
	return (e == ESP_OK) ? (int)len : (e == ESP_ERR_TIMEOUT ? 0 : SE_T_ERR_IO);
}

#else /* host stub */

static int stub_i2c_init(void) { return SE_T_OK; }
static void stub_i2c_cs(se_chip c, bool a) { if (a) g_cur = c; }
static void stub_i2c_reset(se_chip c) { (void)c; }
static int stub_i2c_write(const uint8_t *b, size_t n) { (void)b; (void)n; return SE_T_OK; }
static int stub_i2c_read(uint8_t *b, size_t n, uint32_t t) { (void)b; (void)n; (void)t; return 0; }

#define esp32_i2c_init  stub_i2c_init
#define esp32_i2c_cs    stub_i2c_cs
#define esp32_i2c_reset stub_i2c_reset
#define esp32_i2c_write stub_i2c_write
#define esp32_i2c_read  stub_i2c_read

#endif /* ESP_PLATFORM */

int se_esp32_i2c_make_transport(const se_esp32_i2c_config *cfg,
                                se_transport_t *out)
{
	if (!cfg || !out)
		return -1;
	g_cfg = *cfg;
	out->init = esp32_i2c_init;
	out->cs = esp32_i2c_cs;
	out->reset = esp32_i2c_reset;
	out->write = esp32_i2c_write;
	out->read = esp32_i2c_read;
	return 0;
}
