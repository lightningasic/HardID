/*
 * HardID Hardware Wallet — ESP32-P4 SPI transport for dual ACL16
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * ESP-IDF implementation guarded by ESP_PLATFORM. On the host a recording
 * stub compiles in so logic (CS sequencing, reset pulse, read/write
 * partitioning) is testable without hardware.
 */

#include "se_transport_esp32.h"
#include <string.h>

static se_esp32_spi_config g_cfg;

#ifdef ESP_PLATFORM

#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static spi_device_handle_t g_spi;

static void gpio_out(int pin, int level)
{
	gpio_set_level((gpio_num_t)pin, level);
}

static int esp32_init(void)
{
	spi_bus_config_t bus = {
		.mosi_io_num = g_cfg.gpio_mosi,
		.miso_io_num = g_cfg.gpio_miso,
		.sclk_io_num = g_cfg.gpio_sclk,
		.quadwp_io_num = -1,
		.quadhd_io_num = -1,
	};
	if (spi_bus_initialize((spi_host_device_t)g_cfg.spi_host, &bus,
	                       SPI_DMA_CH_AUTO) != ESP_OK)
		return SE_T_ERR_IO;

	spi_device_interface_config_t dev = {
		.clock_speed_hz = g_cfg.clock_hz,
		.mode = g_cfg.spi_mode,
		.spics_io_num = -1,            /* CS driven manually per chip */
		.queue_size = 1,
	};
	if (spi_bus_add_device((spi_host_device_t)g_cfg.spi_host, &dev, &g_spi) != ESP_OK)
		return SE_T_ERR_IO;

	gpio_set_direction((gpio_num_t)g_cfg.gpio_cs1, GPIO_MODE_OUTPUT);
	gpio_set_direction((gpio_num_t)g_cfg.gpio_cs2, GPIO_MODE_OUTPUT);
	gpio_out(g_cfg.gpio_cs1, 1);       /* deassert both (active low) */
	gpio_out(g_cfg.gpio_cs2, 1);
	if (g_cfg.gpio_reset >= 0) {
		gpio_set_direction((gpio_num_t)g_cfg.gpio_reset, GPIO_MODE_OUTPUT);
		gpio_out(g_cfg.gpio_reset, 1); /* out of reset */
	}
	return SE_T_OK;
}

static void esp32_cs(se_chip chip, bool active)
{
	int pin = (chip == SE_CS_1) ? g_cfg.gpio_cs1 : g_cfg.gpio_cs2;
	gpio_out(pin, active ? 0 : 1);     /* active low */
	if (active)
		for (volatile int i = 0; i < 100; i++);  /* CS setup delay */
}

static void esp32_reset(se_chip chip)
{
	(void)chip;
	if (g_cfg.gpio_reset < 0)
		return;
	gpio_out(g_cfg.gpio_reset, 0);
	vTaskDelay(pdMS_TO_TICKS(5));
	gpio_out(g_cfg.gpio_reset, 1);
	vTaskDelay(pdMS_TO_TICKS(10));
}

static int esp32_write(const uint8_t *buf, size_t len)
{
	spi_transaction_t t = {
		.length = len * 8,
		.tx_buffer = buf,
	};
	return spi_device_transmit(g_spi, &t) == ESP_OK ? SE_T_OK : SE_T_ERR_IO;
}

static int esp32_read(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
	/* SPI full-duplex read: clock out zeros, capture MISO. Timeout handled
	 * by bounding the transaction; ESP-IDF blocking call returns when done. */
	spi_transaction_t t = {
		.length = len * 8,
		.rxlength = len * 8,
		.rx_buffer = buf,
		.tx_buffer = NULL,
	};
	(void)timeout_ms;
	return spi_device_transmit(g_spi, &t) == ESP_OK ? (int)len : SE_T_ERR_IO;
}

#else /* ---- host recording stub ---- */

#define ESP32_STUB_LOG_MAX 1024
static uint8_t g_stub_written[ESP32_STUB_LOG_MAX];
static size_t g_stub_written_len;
static int g_stub_init_calls;
static int g_stub_cs_log[64];
static int g_stub_cs_n;
static int g_stub_reset_pulses;
/* scripted read responses for host tests */
static const uint8_t *g_stub_rx;
static size_t g_stub_rx_len, g_stub_rx_pos;

static void stub_cs(se_chip chip, bool active)
{
	if (g_stub_cs_n < 64)
		g_stub_cs_log[g_stub_cs_n++] = (chip == SE_CS_1 ? 1 : 2) * (active ? 1 : -1);
}

static void stub_reset(se_chip chip)
{
	(void)chip;
	g_stub_reset_pulses++;
}

static int stub_init(void)
{
	g_stub_init_calls++;
	return SE_T_OK;
}

static int stub_write(const uint8_t *buf, size_t len)
{
	if (g_stub_written_len + len > ESP32_STUB_LOG_MAX)
		return SE_T_ERR_IO;
	memcpy(g_stub_written + g_stub_written_len, buf, len);
	g_stub_written_len += len;
	return SE_T_OK;
}

static int stub_read(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
	(void)timeout_ms;
	if (g_stub_rx_pos >= g_stub_rx_len)
		return 0;
	size_t avail = g_stub_rx_len - g_stub_rx_pos;
	size_t take = avail < len ? avail : len;
	memcpy(buf, g_stub_rx + g_stub_rx_pos, take);
	g_stub_rx_pos += take;
	return (int)take;
}

/* unify names with the ESP_PLATFORM branch */
#define esp32_init  stub_init
#define esp32_cs    stub_cs
#define esp32_reset stub_reset
#define esp32_write stub_write
#define esp32_read  stub_read

#endif /* ESP_PLATFORM */

int se_esp32_spi_make_transport(const se_esp32_spi_config *cfg,
                                se_transport_t *out)
{
	if (!cfg || !out)
		return -1;
	g_cfg = *cfg;
	out->init = esp32_init;
	out->cs = esp32_cs;
	out->reset = esp32_reset;
	out->write = esp32_write;
	out->read = esp32_read;
	return 0;
}

/* ---- host-test accessors (only meaningful in the stub build) ---- */
#ifndef ESP_PLATFORM
int  se_esp32_stub_init_calls(void)      { return g_stub_init_calls; }
int  se_esp32_stub_reset_pulses(void)    { return g_stub_reset_pulses; }
const int *se_esp32_stub_cs_log(int *n)  { *n = g_stub_cs_n; return g_stub_cs_log; }
const uint8_t *se_esp32_stub_written(size_t *n) { *n = g_stub_written_len; return g_stub_written; }
void se_esp32_stub_set_rx(const uint8_t *rx, size_t len)
{
	g_stub_rx = rx; g_stub_rx_len = len; g_stub_rx_pos = 0;
}
void se_esp32_stub_reset(void)
{
	g_stub_written_len = 0; g_stub_init_calls = 0;
	g_stub_cs_n = 0; g_stub_reset_pulses = 0;
	g_stub_rx = 0; g_stub_rx_len = 0; g_stub_rx_pos = 0;
}
#endif
