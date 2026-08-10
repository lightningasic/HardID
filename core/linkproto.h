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
 * manual: the host sends a digest (tx hash) it will not sign blind, the
 * device shows it and asks the user to confirm on the screen, and only then
 * signs. Per the single-verb contract (PRD §3.4) the interface accepts
 * exactly ONE operation — SIGN. It deliberately has NO other surface: no
 * key/seed/xpub transfer, no status/config reads, no generic data channel.
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
 * config surface). */
#define HD_CMD_SIGN           0x03u   /* payload: digest32; device shows + PIN-gates */

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

/* How many bytes the caller must hold for the encoding APIs. Replies may
 * carry a 4-byte rc prefix + a 64-byte signature, so size for that. */
#define HD_LINK_MAX_FRAME (HD_LINK_HDR_LEN + 4u + 64u + 2u)

#ifdef __cplusplus
}
#endif

#endif /* HARDID_LINKPROTO_H */