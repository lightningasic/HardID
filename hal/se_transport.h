/*
 * HardID Hardware Wallet — SE transport abstraction (SPI/I2C/UART)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * The two ACL16 secure elements sit on the bus behind a common transport.
 * This header defines the byte-level transport contract; the platform
 * (ESP32-P4 SPI master / I2C master / UART) provides the hooks. Keeping
 * transport separate from the APDU layer means the ACL16 driver is
 * bus-agnostic and host-testable with a loopback transport.
 */

#ifndef HARDID_SE_TRANSPORT_H
#define HARDID_SE_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Transport error codes */
#define SE_T_OK        0
#define SE_T_ERR_IO   -1   /* bus error */
#define SE_T_ERR_TIMEOUT -2
#define SE_T_ERR_PARAM  -3

/* Which physical SE a transaction targets (chip select routing). */
typedef enum {
	SE_CS_1 = 0,   /* SE1 "vault": seed / keys / signing / TRNG#1 */
	SE_CS_2 = 1,   /* SE2 "guard": PIN / policy / monotonic / TRNG#2 */
} se_chip;

/* Byte-level transport hooks. `timeout_ms` applies per read; write is
 * expected to complete or fail fast. */
typedef struct {
	/* Bring up clocks, GPIO, SPI/I2C/UART peripheral. SE_T_OK on success. */
	int (*init)(void);

	/* Drive the chip-select line for `chip`. active=true asserts. */
	void (*cs)(se_chip chip, bool active);

	/* Pulse the SE reset line (shared or per-chip). */
	void (*reset)(se_chip chip);

	/* Write len bytes. Returns SE_T_OK or SE_T_ERR_IO. */
	int (*write)(const uint8_t *buf, size_t len);

	/* Read up to len bytes into buf within timeout_ms.
	 * Returns number of bytes read (>0), 0 on timeout, SE_T_ERR_IO on error. */
	int (*read)(uint8_t *buf, size_t len, uint32_t timeout_ms);
} se_transport_t;

/* Set the active transport (called once at board init). */
void se_transport_set(const se_transport_t *t);
const se_transport_t *se_transport_get(void);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_SE_TRANSPORT_H */
