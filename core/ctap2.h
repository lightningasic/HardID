/*
 * HardID Hardware Wallet — CTAP2 command parsing / dispatch
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Entry point for the CTAP2 protocol layer. Consumes a full CTAP2 request
 * message (command byte + CBOR payload) from the CTAPHID framing layer
 * (core/fido_ctaphid.c) and produces the CTAP2 response message
 * (status byte + CBOR payload). Parsing is bounded and strict enough to
 * reject malformed CBOR (CTAP2_ERR_INVALID_CBOR) while tolerating unknown
 * map members per CTAP2 §6.1.
 */

#ifndef HARDID_CTAP2_H
#define HARDID_CTAP2_H

#include <stdint.h>
#include <stddef.h>
#include "fido.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Handle one CTAP2 request message.
 *
 * msg      : full CTAP2 message: msg[0] = CTAP2_CMD_*, msg[1..] = CBOR payload
 * len      : length of msg
 * resp     : caller-provided buffer for the response message
 * resp_cap : capacity of resp (recommend CTAPHID_MAX_MSG)
 * resp_len : on success (return == CTAP2_OK), number of bytes written to
 *            resp; resp[0] = status byte, resp[1..] = CBOR payload
 *
 * Returns the CTAP2 status byte (0x00 success). On any status, the caller
 * (fido_ctaphid.c) is responsible for producing the correct CTAPHID packet
 * (CBOR response body or CTAPHID_ERROR).
 */
int ctap2_handle(const uint8_t *msg, size_t len,
                 uint8_t *resp, size_t resp_cap, size_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_CTAP2_H */