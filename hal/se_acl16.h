/*
 * OpenShield Hardware Wallet — ACL16 secure-element driver (APDU layer)
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * ISO 7816-4 style APDU command layer over se_transport. The instruction
 * (INS) opcodes are placeholders pending the ACL16 datasheet — every opcode
 * lives in se_acl16_opcodes.h so filling in the real values is a one-file
 * change once the vendor NDA documentation arrives.
 *
 * The driver exposes two instances (SE1 vault, SE2 guard) behind a small
 * context so the composite layer can route without globals beyond the
 * transport pointer.
 */

#ifndef OPENSHIELD_SE_ACL16_H
#define OPENSHIELD_SE_ACL16_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "se_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* APDU status words (ISO 7816-4) */
#define SE_SW_OK            0x9000
#define SE_SW_WRONG_LENGTH  0x6700
#define SE_SW_AUTH_FAILED   0x6982
#define SE_SW_LOCKED        0x6983
#define SE_SW_NOT_INIT      0x6985
#define SE_SW_WRONG_DATA    0x6A80
#define SE_SW_UNKNOWN       0x6F00

/* Per-chip driver context (one for SE1, one for SE2). */
typedef struct {
	se_chip chip;
	uint32_t default_timeout_ms;
} se_acl16_t;

void se_acl16_init_ctx(se_acl16_t *ctx, se_chip chip);

/* Raw APDU exchange: send CLA INS P1 P2 [Lc data] [Le], receive
 * [response] SW1 SW2. Returns the status word (e.g. SE_SW_OK); response
 * bytes (without SW) are written to resp and *resp_len updated. */
int se_acl16_apdu(se_acl16_t *ctx,
                  uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                  const uint8_t *data, size_t data_len,
                  uint8_t *resp, size_t *resp_len, size_t resp_max);

/* High-level operations used by the composite driver (map to se_driver_t). */
int  se_acl16_get_random(se_acl16_t *ctx, uint8_t *buf, size_t len);
int  se_acl16_store_seed(se_acl16_t *ctx, const uint8_t *seed32);
int  se_acl16_is_initialized(se_acl16_t *ctx, bool *initialized);
int  se_acl16_sign_digest(se_acl16_t *ctx, const uint32_t *path, size_t path_len,
                          const uint8_t *digest32, uint8_t *sig64, uint8_t *recid);
int  se_acl16_get_xpub(se_acl16_t *ctx, const uint32_t *path, size_t path_len,
                       char *xpub_out, size_t xpub_max);
int  se_acl16_verify_pin(se_acl16_t *ctx, const uint8_t *pin, size_t len,
                         uint32_t *wait_seconds, bool *is_duress);
int  se_acl16_policy_authorize(se_acl16_t *ctx, uint32_t policy_id, uint64_t amount);
int  se_acl16_monotonic_read(se_acl16_t *ctx, uint32_t *counter);
int  se_acl16_monotonic_increment(se_acl16_t *ctx);
int  se_acl16_attest(se_acl16_t *ctx, const uint8_t *challenge32,
                     uint8_t *response, size_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif /* OPENSHIELD_SE_ACL16_H */
