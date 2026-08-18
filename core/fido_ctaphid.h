/*
 * HardID Hardware Wallet — CTAPHID transport framing
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * CTAPHID (CTAP2 §11.2) over USB HID. Splits a CTAP2 message stream into
 * 64-byte HID packets and reassembles incoming packets into messages:
 *
 *   INIT packet: cid(4) || cmd(1,0x80 set) || bcnt(2) || data(≤57)  ->64B
 *   CONT packet: cid(4) || seq(1, 0x80 clear)            || data(≤59)  ->64B
 *
 * A message = one INIT packet (first ≤57 bytes plus BCNT) followed by zero
 * or more CONT packets with seq 0,1,2,…  Any packet whose 5th byte has
 * bit7 set starts a new message; a packet with bit7 clear is a
 * continuation of the message currently being reassembled. Responses are
 * emitted with the same framing (INIT first, then CONTs).
 *
 * Error semantics follow the spec and the reference implementations
 * (libfido2/src/io.c, python-fido2/fido2/hid/__init__.py, solo1):
 *   - stray/out-of-order CONT, seq mismatch  -> CTAP1_ERR_INVALID_SEQUENCE
 *   - BCNT > CTAPHID_MAX_MSG                 -> CTAP1_ERR_INVALID_LENGTH
 *   - command while a message is in flight   -> CTAP1_ERR_CHANNEL_BUSY
 *   - packet addressed to an unknown CID     -> CTAP1_ERR_INVALID_CHANNEL
 *   - INIT on broadcast allocates a channel, reply carries new CID
 * There is NO CRC field in CTAPHID — errata design doc §7 "坏 CRC".
 *
 * On completion of a CBOR message the caller-provided dispatch() runs with
 * the raw message bytes; its outcome is staged as a CTAPHID_CBOR response
 * message (status byte, then CBOR on success). Framer-level errors go out
 * as a CTAPHID_ERROR packet carrying a single status byte.
 */

#ifndef HARDID_CTAPHID_H
#define HARDID_CTAPHID_H

#include <stdint.h>
#include <stddef.h>
#include "fido.h"

#ifdef __cplusplus
extern "C" {
#endif

/* One active channel + one in-flight message (first version; resident key
 * management and multi-channel are out of scope per design §3). */
typedef struct {
	uint32_t cid;        /* our channel id (allocated via INIT) */
	uint32_t seed;       /* cid allocator counter */

	/* receive state */
	uint8_t  rx_ready;
	uint16_t rx_len;
	uint16_t rx_pos;
	uint8_t  rx_seq;
	uint8_t  rx_cmd;
	uint8_t  rx_buf[CTAPHID_MAX_MSG];

	/* transmit (staged response) state */
	uint8_t  tx_buf[CTAPHID_MAX_MSG];
	uint16_t tx_len;
	uint16_t tx_sent;
	uint8_t  tx_cmd;
	uint32_t cid_target;   /* channel the response is addressed to */
	uint8_t  tx_seq;

	/* dispatch: called with the complete request message (CBOR channel).
	 * Returns CTAP2 status; on success writes the CBOR payload to out and
	 * sets *out_len. NULL means "no dispatcher wired" (invalid command). */
	int (*dispatch)(const uint8_t *msg, size_t msg_len,
	                uint8_t *out, size_t out_cap, size_t *out_len);

	/* msg_dispatch: called with a complete CTAPHID_MSG (U2F/CTAP1 APDU).
	 * Writes the APDU response (data || SW1SW2) to out, sets *out_len;
	 * return value unused (the APDU status word carries the outcome).
	 * NULL falls back to CTAP1_ERR_INVALID_COMMAND, preserving the
	 * CTAP2-only behavior for builds that do not wire a U2F handler. */
	void (*msg_dispatch)(const uint8_t *apdu, size_t apdu_len,
	                     uint8_t *out, size_t out_cap, size_t *out_len);
} ctaphid_t;

void ctaphid_init(ctaphid_t *h);

/* Feed one 64-byte input packet; emit up to max_out response packets into
 * out[] (each 64 bytes). Returns the number emitted. Caller must keep
 * calling with an empty input buffer (pkt == NULL) until the return value
 * is 0 to drain a long staged response. Requires max_out >= 1. */
int ctaphid_feed(ctaphid_t *h, const uint8_t *pkt,
                 uint8_t (*out)[CTAPHID_PACKET_SIZE], int max_out);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_CTAPHID_H */