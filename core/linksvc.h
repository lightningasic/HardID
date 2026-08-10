/*
 * HardID Hardware Wallet — host-link service (firmware side)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Turns a validated host frame into a signed reply. Signing is delegated to
 * the SAME service the on-device SIGN menu uses (os_signsvc_delegate), so a
 * host-requested signature goes through identical parse → WYSIWYS confirm →
 * real chain sighash → SE-sign steps. This module is host-testable.
 *
 * Single-verb contract (PRD §3.4): the ONLY operation this service accepts
 * is SIGN. Every other command type is rejected; there is no status, no
 * xpub, no config, no generic data surface. The only data that ever goes
 * back to the host is a signature (public knowledge). Seeds and private
 * keys never leave the SE.
 */

#ifndef HARDID_LINKSVC_H
#define HARDID_LINKSVC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "signsvc.h"   /* os_sign_outcome / os_tx_intent */

#ifdef __cplusplus
extern "C" {
#endif

/* Handle one complete, already-parsed request (type/seq/payload) and write a
 * reply frame into out (returns length, or -1 on encode error).
 *
 * `ui_confirm_tx` is the on-device Clear-Sign hook for HD_CMD_SIGN: it is
 * passed the parsed, firmware-verified intent and returns true to allow
 * signing, false to refuse. NULL is NEVER a bypass — signsvc maps a NULL
 * confirm to a hard abort. The SE session must already be PIN-unlocked by
 * the transport (boot/UI policy). */
int hd_link_serve(bool (*ui_confirm_tx)(const os_tx_intent *),
                  uint8_t type, uint16_t seq,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_LINKSVC_H */
