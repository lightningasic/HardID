/*
 * HardID Hardware Wallet — host<->device link protocol
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * A small, framed, checksummed command channel between the host computer and
 * the wallet. It carries a complete request as one frame so the device can
 * validate it before acting, and returns one frame per request. The transport
 * (USB/SPI/JTAG emulated serial) is injected by the caller, so this module is
 * fully testable on the host.
 *
 * THIS SAME LAYER IS WHAT ENABLES the "verify a transaction" goal in the
 * manual: the host sends a structured sign request (PRD §3.4) — app id,
 * BIP32 derivation path, and the raw transaction bytes — and the device
 * renders the intent on screen, asks the user to confirm, and only then
 * signs (WYSIWYS). The request is routed through the SAME sign service as
 * the on-device SIGN menu (os_signsvc_delegate), so both paths are
 * provably identical. Per the single-verb contract (PRD §3.4) the interface
 * accepts exactly ONE operation — SIGN. It deliberately has NO other
 * surface: no key/seed/xpub transfer, no status/config reads, no generic
 * data channel.
 */

#ifndef HARDID_LINKPROTO_H
#define HARDID_LINKPROTO_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- frame format ----
 *   magic  : 0xA5
 *   ver    : 0x01
 *   type   : command or reply
 *   flags  : reserved (0)
 *   length : 2-byte big-endian payload length
 *   seq    : 1-byte, echoed by the reply (replay/drop detection)
 *   payload: <length> bytes
 *   crc    : 2-byte big-endian CRC-16/CCITT over magic..payload
 * Total header is 8 bytes.
 */
#define HD_LINK_MAGIC      0xA5u
#define HD_LINK_VER        0x01u
#define HD_LINK_HDR_LEN    8u
#define HD_LINK_CRC_INIT   0xFFFFu

/* command types (host -> device) — single-verb contract (PRD §3.4):
 * the ONLY callable operation is SIGN. Every other type is rejected by
 * the service (and must never be added: no key export, no status, no
 * config surface).
 *
 * SIGN payload (structured, WYSIWYS — routed through os_signsvc_delegate):
 *   [0]        app_id_len N (1..HD_LINK_APP_ID_MAX)
 *   [1..N]     app_id, ASCII, no NUL (e.g. "eth" / "btc")
 *   [N+1]      path_len P (1..HD_LINK_PATH_MAX)
 *   [N+2 .. N+1+4P]  P × 4-byte big-endian BIP32 path components
 *                    (hardened flag OS_PATH_HARDENED included)
 *   [rest]     raw transaction bytes: PSBT (BTC family) or raw EVM tx
 *              (EVM family). Chains with no firmware parser are refused
 *              by signsvc. Max HD_LINK_MAX_TX bytes.
 *
 * SIGN reply (device -> host) on OK:
 *   sig_count(4 BE) | [ sig64(64) | recid(1) ] × sig_count
 * sig_count is 1 for EVM (one compact r||s + recovery id); for BTC it is the
 * number of inputs signed, each carrying its own compact signature. The host
 * assembles the final signatures/witnesses from these (core/tx_asm.c) — the
 * device returns compact signatures only, never a serialized tx.
 *
 * The reply payload can reach 4 + OS_PSBT_MAX_INPUTS×65 bytes for a
 * multi-input BTC PSBT; it still fits HD_LINK_MAX_FRAME. */
#define HD_CMD_SIGN           0x03u

/* SIGN payload size bounds. HD_LINK_MAX_FRAME must hold the largest
 * request (app_id + path + tx) plus header + crc. */
#define HD_LINK_APP_ID_MAX    16u
#define HD_LINK_PATH_MAX      10u
#define HD_LINK_MAX_TX        2048u
#define HD_LINK_MAX_PAYLOAD   (1u + HD_LINK_APP_ID_MAX + 1u + HD_LINK_PATH_MAX * 4u + HD_LINK_MAX_TX)

/* reply types (device -> host) */
#define HD_REPLY_OK           0x81u
#define HD_REPLY_ERR          0x82u
#define HD_ERR_PARAM        (-4)
#define HD_ERR_STATE        (-5)
#define HD_ERR_AUTH         (-2)
#define HD_ERR_INTERNAL     (-6)

/* Encode a request frame. seq is the caller's monotonic id. Returns bytes
 * written (<= out_max) or -1 if the payload/out do not fit. */
int hd_link_frame_cmd(uint8_t type, uint16_t seq,
                      const uint8_t *payload, size_t plen,
                      uint8_t *out, size_t out_max);

/* Encode a reply frame. Returns bytes written or -1. */
int hd_link_frame_reply(uint8_t type, uint16_t seq, int32_t err_rc,
                        const uint8_t *payload, size_t plen,
                        uint8_t *out, size_t out_max);

/* Parse/validate one frame. Writes *type, *seq, and points *payload at the
 * interior (with *plen). Returns 0 on a well-formed non-corrupt frame, or -1
 * if the CRC fails / magic is wrong. `buf_len` bounds the input buffer; a
 * frame larger than buf_len is an error (does not try to parse). */
int hd_link_parse(const uint8_t *buf, size_t buf_len,
                  uint8_t *type, uint16_t *seq,
                  const uint8_t **payload, size_t *plen);

/* CRC-16/CCITT-FALSE (poly 0x1021, init 0x0000), big-endian byte order,
 * exposed for the transport so it can stream-accumulate and re-check. */
uint16_t hd_link_crc(const uint8_t *data, size_t len);

/* How many bytes the caller must hold for the encoding APIs. Sized for the
 * largest SIGN request frame; replies are smaller (4-byte rc + sig). */
#define HD_LINK_MAX_FRAME (HD_LINK_HDR_LEN + HD_LINK_MAX_PAYLOAD + 2u)

#ifdef __cplusplus
}
#endif

#endif /* HARDID_LINKPROTO_H */