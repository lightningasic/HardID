/*
 * HardID Hardware Wallet — board bring-up for ESP32-P4 + dual ACL16
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 */

#include "se_board.h"
#include "se_transport.h"
#include "se_transport_esp32.h"

/* Board pinout (see se_transport_esp32.h) */
static const se_esp32_spi_config board_cfg = {
	.spi_host = 2,             /* SPI2_HOST on ESP32-P4 */
	.gpio_sclk = 12,
	.gpio_mosi = 11,
	.gpio_miso = 13,
	.gpio_cs1 = 10,            /* SE1 vault */
	.gpio_cs2 = 9,             /* SE2 guard */
	.gpio_reset = 8,
	.clock_hz = 10000000,      /* 10 MHz — conservative for ACL16 */
	.spi_mode = 0,
};

static se_transport_t board_transport;

int os_board_se_init(void)
{
	if (se_esp32_spi_make_transport(&board_cfg, &board_transport) != 0)
		return SE_ERR_COMM;
	se_transport_set(&board_transport);
	return se_active()->init();
}
