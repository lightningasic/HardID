/*
 * HardID Hardware Wallet — ESP32-P4 SPI transport for dual ACL16
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Implements se_transport_t on the ESP32-P4's SPI2/SPI3 master peripheral
 * for two ACL16 secure elements on one shared bus with per-chip CS lines.
 * ESP-IDF calls are guarded by ESP_PLATFORM so the file also compiles on
 * the host (with a recording stub) for logic tests.
 *
 * Wiring (suggested):
 *   SCLK  = GPIO12   MOSI = GPIO11   MISO = GPIO13
 *   CS1   = GPIO10   (SE1 vault)
 *   CS2   = GPIO9    (SE2 guard)
 *   RESET = GPIO8    (shared SE reset, active low)
 */

#ifndef HARDID_SE_TRANSPORT_ESP32_H
#define HARDID_SE_TRANSPORT_ESP32_H

#include "se_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int spi_host;        /* ESP-IDF spi_host_device_t (SPI2_HOST / SPI3_HOST) */
	int gpio_sclk;
	int gpio_mosi;
	int gpio_miso;
	int gpio_cs1;        /* SE1 chip select */
	int gpio_cs2;        /* SE2 chip select */
	int gpio_reset;      /* shared reset, active low; <0 = unused */
	int clock_hz;        /* SPI clock, e.g. 10000000 (10 MHz) */
	int spi_mode;        /* 0..3 */
} se_esp32_spi_config;

/* Fill a se_transport_t that talks to the two ACL16 over SPI.
 * Returns 0 on success. Does NOT init the peripheral — call the returned
 * transport's init() (normally via se_active()->init()). */
int se_esp32_spi_make_transport(const se_esp32_spi_config *cfg,
                                se_transport_t *out);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SE_TRANSPORT_ESP32_H */
