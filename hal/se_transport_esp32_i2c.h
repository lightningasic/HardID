/*
 * OpenShield Hardware Wallet — ESP32-P4 I2C transport for ACL16 (alternative)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Alternative to SPI for ACL16 variants/boards that use I2C. Each ACL16 is
 * an I2C slave with its own 7-bit address; "chip select" becomes the slave
 * address rather than a GPIO. Guarded by ESP_PLATFORM like the SPI variant.
 */

#ifndef OPENSHIELD_SE_TRANSPORT_ESP32_I2C_H
#define OPENSHIELD_SE_TRANSPORT_ESP32_I2C_H

#include "se_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	int i2c_port;        /* ESP-IDF i2c_port_t */
	int gpio_sda;
	int gpio_scl;
	uint8_t addr_se1;    /* 7-bit I2C address of SE1 */
	uint8_t addr_se2;    /* 7-bit I2C address of SE2 */
	int clock_hz;        /* e.g. 400000 (400 kHz fast mode) */
} se_esp32_i2c_config;

int se_esp32_i2c_make_transport(const se_esp32_i2c_config *cfg,
                                se_transport_t *out);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SE_TRANSPORT_ESP32_I2C_H */
