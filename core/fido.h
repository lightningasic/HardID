/*
 * HardID Hardware Wallet — FIDO2/CTAP2 data structures
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * FIDO2 WebAuthn authenticator data structures: credential model,
 * authenticator data (authData), COSE public keys and the CTAP2/CTAPHID
 * protocol constants. Data flows:
 *
 *   host --CTAPHID frames--> fido_ctaphid.c --CTAP2 CBOR--> ctap2.c
 *        --fido_core--> se fido_cred_* (SE P-256 sign)
 *
 * Only the public key material ever crosses the SE boundary; credential
 * IDs are opaque SE-produced blobs (see se_driver.h fido_cred_*).
 */

#ifndef HARDID_FIDO_H
#define HARDID_FIDO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "se_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- WebAuthn authenticator data (authData) layout ----
 * rpIdHash(32) || flags(1) || signCount(4) || attestedCredentialData*
 * attestedCredentialData (present iff AT=1):
 *   aaguid(16) || credIdLen(2) || credID || COSE pubkey (CBOR map, alg -7)
 */
#define FIDO_AT_FLAG_UP      0x01
#define FIDO_AT_FLAG_UV      0x04
#define FIDO_AT_FLAG_AT      0x40
#define FIDO_AT_RPID_HASH_LEN 32
#define FIDO_AT_HEADER_LEN   (FIDO_AT_RPID_HASH_LEN + 1 + 4)

/* AAGUID (product identifier, build-time fixed per decision A1). 16 bytes. */
#define FIDO_AAGUID_LEN      16
extern const uint8_t fido_aaguid[FIDO_AAGUID_LEN];

/* COSE key for ES256 (alg -7), EC2 kty 2, P-256 crv 1. */
#define COSE_KTY_EC2  2
#define COSE_ALG_ES256 (-7)
#define COSE_CRV_P256 1

/* ---- CTAP2 command codes (CTAP2 §8.1) ---- */
#define CTAP2_CMD_MAKE_CREDENTIAL  0x01
#define CTAP2_CMD_GET_ASSERTION    0x02
#define CTAP2_CMD_GET_INFO         0x04
#define CTAP2_CMD_CLIENT_PIN       0x06
#define CTAP2_CMD_RESET            0x07
#define CTAP2_CMD_GET_NEXT_ASSERT  0x08
#define CTAP2_CMD_CONFIG           0x0D

/* ---- CTAP2 status codes (CTAP2 §8.2); sent as first byte of a CBOR
 * response message, then followed by the CBOR payload on success. ---- */
#define CTAP2_OK                    0x00
#define CTAP1_ERR_INVALID_COMMAND   0x01
#define CTAP1_ERR_INVALID_PARAMETER 0x02
#define CTAP1_ERR_INVALID_LENGTH    0x03
#define CTAP1_ERR_INVALID_SEQUENCE  0x04
#define CTAP1_ERR_TIMEOUT           0x05
#define CTAP1_ERR_CHANNEL_BUSY      0x06
#define CTAP1_ERR_LOCK_REQUIRED     0x0A
#define CTAP1_ERR_INVALID_CHANNEL   0x0B
#define CTAP1_ERR_OTHER             0x7F
#define CTAP2_ERR_CBOR_UNEXPECTED_TYPE 0x11
#define CTAP2_ERR_INVALID_CBOR      0x12
#define CTAP2_ERR_MISSING_PARAMETER 0x14
#define CTAP2_ERR_LIMIT_EXCEEDED    0x15
#define CTAP2_ERR_CREDENTIAL_EXCLUDED 0x19
#define CTAP2_ERR_PROCESSING        0x21
#define CTAP2_ERR_INVALID_CREDENTIAL 0x22
#define CTAP2_ERR_USER_ACTION_PENDING 0x23
#define CTAP2_ERR_OPERATION_PENDING 0x24
#define CTAP2_ERR_NO_OPERATIONS     0x25
#define CTAP2_ERR_UNSUPPORTED_ALGORITHM 0x26
#define CTAP2_ERR_OPERATION_DENIED  0x27
#define CTAP2_ERR_KEY_STORE_FULL    0x28
#define CTAP2_ERR_UNSUPPORTED_OPTION 0x2B
#define CTAP2_ERR_INVALID_OPTION    0x2C
#define CTAP2_ERR_KEEPALIVE_CANCEL  0x2D
#define CTAP2_ERR_NO_CREDENTIALS    0x2E
#define CTAP2_ERR_USER_ACTION_TIMEOUT 0x2F
#define CTAP2_ERR_NOT_ALLOWED       0x30
#define CTAP2_ERR_REQUEST_TOO_LARGE 0x39
#define CTAP2_ERR_ACTION_TIMEOUT    0x3A
#define CTAP2_ERR_UP_REQUIRED       0x3B

/* ---- CTAPHID constants (CTAP2 §11.2) ---- */
#define CTAPHID_PACKET_SIZE   64
#define CTAPHID_INIT_HEADER   7   /* cid(4) + cmd(1) + bcnt(2) */
#define CTAPHID_CONT_HEADER   5   /* cid(4) + seq(1) */
#define CTAPHID_MAX_MSG       (CTAPHID_PACKET_SIZE - CTAPHID_INIT_HEADER + \
                               128 * (CTAPHID_PACKET_SIZE - CTAPHID_CONT_HEADER))
#define CTAPHID_BROADCAST_CID 0xFFFFFFFFu

#define CTAPHID_PING    0x01
#define CTAPHID_MSG     0x03
#define CTAPHID_LOCK    0x04
#define CTAPHID_INIT    0x06
#define CTAPHID_WINK    0x08
#define CTAPHID_CBOR    0x10
#define CTAPHID_CANCEL  0x11
#define CTAPHID_KEEPALIVE 0x3B
#define CTAPHID_ERROR   0x3F

#define CTAPHID_CAP_WINK 0x01
#define CTAPHID_CAP_CBOR 0x04
#define CTAPHID_CAP_NMSG 0x08

/* CTAPHID protocol version (this implementation). */
#define CTAPHID_PROTOCOL_VERSION 2

/* ---- GetInfo response (design doc §3.2); regs/options that are static ---- */
#define FIDO_GETINFO_MAX_MSG_SIZE      7609
#define FIDO_GETINFO_MAX_CRED_ID_LEN   128
#define FIDO_GETINFO_MAX_CRED_COUNT    8

#ifdef __cplusplus
}
#endif

#endif /* HARDID_FIDO_H */