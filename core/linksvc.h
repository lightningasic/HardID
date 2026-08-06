/*
 * HardID Hardware Wallet — host-link service (firmware side)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Turns a validated host frame into a signed/status reply. All SE interaction
 * goes through a small injected vtable so this module is host-testable without
 * the real backend and portable to any transport.
 *
 * The only secret-adjacent data that ever goes back to the host is a signature
 * (public knowledge) or an xpub (public). Seeds and private keys never leave
 * the SE. Standard sign requires a prior unlock() on the SAME session.
 */

#ifndef HARDID_LINKSVC_H
#define HARDID_LINKSVC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Minimal SE ops the link service needs. The device wraps its real
 * se_driver_t (or mock) behind these. */
typedef struct hd_link_se {
	/* true if a seed is provisioned */
	bool (*is_initialized)(void);
	/* unlock a session with a PIN; 0 = success, negative = auth/param err */
	int (*unlock)(const uint8_t *pin, size_t plen);
	/* sign a 32-byte digest -> 64-byte r||s. Caller may present the digest
	 * visually / voice to the user right before (Clear Sign hook). */
	int (*sign)(const uint8_t *digest32, uint8_t *sig64);
} hd_link_se_t;

/* Handle one complete, already-parsed request (type/seq/payload) and write a
 * reply frame into out (returns length, or -1 on encode error).
 *
 * `ui_confirm_digest` is the on-device Clear-Sign hook: return true to allow
 * signing, false to refuse. Only invoked for HD_CMD_SIGN after a successful
 * unlock. */
int hd_link_serve(const hd_link_se_t *se,
                  bool (*ui_confirm_digest)(const uint8_t *digest32),
                  uint8_t type, uint16_t seq,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t out_max);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_LINKSVC_H */