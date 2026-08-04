/*
 * OpenShield Hardware Wallet — board bring-up for ESP32-P4 + dual ACL16
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 * License: Apache License 2.0
 *
 * Wires the SPI transport + dual-ACL16 composite driver together and
 * exposes a single os_board_se_init() that firmware boot calls.
 */

#ifndef OPENSHIELD_SE_BOARD_H
#define OPENSHIELD_SE_BOARD_H

#include "../core/se_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialize SPI bus + both ACL16 + composite driver. Returns SE_OK. */
int os_board_se_init(void);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SE_BOARD_H */
