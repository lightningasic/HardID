/*
 * HardID Hardware Wallet — CTAPHID transport framing
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Splits/reassembles CTAP2 messages over USB HID. Error and channel
 * semantics follow CTAP2 §11.2 and the reference implementations
 * (libfido2/src/io.c, python-fido2/fido2/hid/__init__.py, solo1):
 *   - stray/out-of-order CONT, seq mismatch  -> INVALID_SEQUENCE
 *   - BCNT > CTAPHID_MAX_MSG                 -> INVALID_LENGTH
 *   - command while reassembling             -> CHANNEL_BUSY
 *   - unknown (non-broadcast) CID            -> INVALID_CHANNEL
 *   - INIT on broadcast: allocate channel; reply (on broadcast) carries
 *     the new CID in a 17-byte payload after the echoed nonce
 * There is NO CRC field in the framing (errata design doc §7 "坏 CRC").
 */

#include "fido_ctaphid.h"
#include <string.h>

void ctaphid_init(ctaphid_t *h)
{
	memset(h, 0, sizeof *h);
}

static uint32_t get_u32(const uint8_t p[4])
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_u16(uint8_t p[2], uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static void put_u32(uint8_t p[4], uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)v;
}

/* ---- staged response emission ---- */

static void stage_tx(ctaphid_t *h, uint8_t cmd, uint32_t target,
                     const uint8_t *data, uint16_t len)
{
	h->tx_cmd = cmd;
	h->cid_target = target;
	if (len > sizeof h->tx_buf)
		len = sizeof h->tx_buf;
	if (data != NULL)
		memcpy(h->tx_buf, data, len);
	h->tx_len = len;
	h->tx_sent = 0;
	h->tx_seq = 0;
}

static void stage_error(ctaphid_t *h, uint32_t target, uint8_t err)
{
	uint8_t b = err;
	stage_tx(h, CTAPHID_ERROR, target, &b, 1);
}

/* Emit up to max_out response packets. Returns the number emitted;
 * caller drains with pkt==NULL calls until 0. */
static int emit_tx(ctaphid_t *h, uint8_t (*out)[CTAPHID_PACKET_SIZE],
                   int max_out)
{
	int n = 0;
	while (h->tx_sent < h->tx_len && n < max_out) {
		uint8_t *p = out[n];
		memset(p, 0, CTAPHID_PACKET_SIZE);
		put_u32(p, h->cid_target);
		if (h->tx_sent == 0) {
			uint16_t room = h->tx_len - h->tx_sent;
			if (room > CTAPHID_PACKET_SIZE - CTAPHID_INIT_HEADER)
				room = CTAPHID_PACKET_SIZE - CTAPHID_INIT_HEADER;
			p[4] = (uint8_t)(h->tx_cmd | 0x80);
			put_u16(p + 5, h->tx_len);
			memcpy(p + CTAPHID_INIT_HEADER,
			       h->tx_buf + h->tx_sent, room);
			h->tx_sent += room;
		} else {
			uint16_t room = h->tx_len - h->tx_sent;
			if (room > CTAPHID_PACKET_SIZE - CTAPHID_CONT_HEADER)
				room = CTAPHID_PACKET_SIZE - CTAPHID_CONT_HEADER;
			p[4] = (uint8_t)(h->tx_seq & 0x7f);
			memcpy(p + CTAPHID_CONT_HEADER,
			       h->tx_buf + h->tx_sent, room);
			h->tx_sent += room;
			h->tx_seq = (uint8_t)(h->tx_seq + 1);
		}
		n++;
	}
	return n;
}

/* ---- dispatch a completed message into a staged response ---- */

static void dispatch_message(ctaphid_t *h)
{
	uint8_t cmd = h->rx_cmd;

	switch (cmd) {
	case CTAPHID_PING:
		stage_tx(h, CTAPHID_PING, h->cid, h->rx_buf, h->rx_len);
		return;
	case CTAPHID_WINK:
		stage_tx(h, CTAPHID_WINK, h->cid, NULL, 0);
		return;
	case CTAPHID_LOCK:
		/* lock released immediately (no session semantics) */
		stage_tx(h, CTAPHID_LOCK, h->cid, NULL, 0);
		return;
	case CTAPHID_CBOR:
		if (h->dispatch != NULL) {
			/* response message: status byte, then CBOR on success */
			uint8_t *out = h->tx_buf + 1;
			size_t cap = sizeof h->tx_buf - 1;
			size_t olen = 0;
			int st = h->dispatch(h->rx_buf, h->rx_len, out, cap, &olen);
			if (olen > cap)
				olen = cap;
			h->tx_buf[0] = (uint8_t)st;
			stage_tx(h, CTAPHID_CBOR, h->cid,
			         h->tx_buf, (uint16_t)(olen + 1));
		} else {
			stage_error(h, h->cid, CTAP1_ERR_INVALID_COMMAND);
		}
		return;
	default:
		/* CTAP1 MSG and any other code: unsupported */
		stage_error(h, h->cid, CTAP1_ERR_INVALID_COMMAND);
		return;
	}
}

int ctaphid_feed(ctaphid_t *h, const uint8_t *pkt,
                 uint8_t (*out)[CTAPHID_PACKET_SIZE], int max_out)
{
	/* Drain previously staged response first. */
	if (h->tx_sent < h->tx_len)
		return emit_tx(h, out, max_out);

	if (pkt == NULL)
		return 0;

	uint8_t b = pkt[4];

	if (b & 0x80) {
		/* ---- INIT packet: new command/continuation start ---- */
		uint32_t cid = get_u32(pkt);
		uint8_t cmd = b & 0x7f;

		if (cid == CTAPHID_BROADCAST_CID) {
			/* Only INIT is legal on broadcast. */
			if (cmd != CTAPHID_INIT)
				return 0;
			uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];
			if (bcnt < 8)
				return 0;     /* malformed: ignore */
			h->cid = (h->seed ? h->seed + 1 : 1);
			while (h->cid == CTAPHID_BROADCAST_CID || h->cid == 0)
				h->cid++;
			h->seed = h->cid;
			/* 17-byte response: nonce(8) || cid(4) || proto(1) ||
			 * major(1) || minor(1) || build(1) || caps(1) */
			uint8_t resp[17];
			memcpy(resp, pkt + CTAPHID_INIT_HEADER, 8);
			put_u32(resp + 8, h->cid);
			resp[12] = CTAPHID_PROTOCOL_VERSION;
			resp[13] = 0;
			resp[14] = 0;
			resp[15] = 0;
			resp[16] = CTAPHID_CAP_CBOR;
			stage_tx(h, CTAPHID_INIT, CTAPHID_BROADCAST_CID,
			         resp, sizeof resp);
			return emit_tx(h, out, max_out);
		}

		/* Non-broadcast command. */
		if (cid != h->cid) {
			stage_error(h, cid, CTAP1_ERR_INVALID_CHANNEL);
			return emit_tx(h, out, max_out);
		}
		if (h->rx_ready) {
			stage_error(h, cid, CTAP1_ERR_CHANNEL_BUSY);
			return emit_tx(h, out, max_out);
		}

		uint16_t bcnt = ((uint16_t)pkt[5] << 8) | pkt[6];
		if (bcnt > CTAPHID_MAX_MSG) {
			stage_error(h, cid, CTAP1_ERR_INVALID_LENGTH);
			return emit_tx(h, out, max_out);
		}

		h->rx_cmd = cmd;
		h->rx_len = bcnt;
		h->rx_pos = 0;
		h->rx_seq = 0;
		h->rx_ready = 1;

		uint16_t take = bcnt;
		if (take > CTAPHID_PACKET_SIZE - CTAPHID_INIT_HEADER)
			take = CTAPHID_PACKET_SIZE - CTAPHID_INIT_HEADER;
		memcpy(h->rx_buf + h->rx_pos,
		       pkt + CTAPHID_INIT_HEADER, take);
		h->rx_pos += take;

		if (h->rx_pos == h->rx_len && bcnt == 0) {
			/* empty message: dispatch immediately (CBOR will
			 * produce an invalid-length via the dispatcher) */
		}
		if (h->rx_pos >= h->rx_len) {
			h->rx_ready = 0;
			dispatch_message(h);
			return emit_tx(h, out, max_out);
		}
		return 0;      /* needs CONT packets */
	}

	/* ---- CONT packet ---- */
	uint32_t cid = get_u32(pkt);
	uint8_t seq = b & 0x7f;

	if (cid != h->cid || !h->rx_ready || seq != h->rx_seq) {
		stage_error(h, cid, CTAP1_ERR_INVALID_SEQUENCE);
		return emit_tx(h, out, max_out);
	}
	uint16_t take = h->rx_len - h->rx_pos;
	if (take > CTAPHID_PACKET_SIZE - CTAPHID_CONT_HEADER)
		take = CTAPHID_PACKET_SIZE - CTAPHID_CONT_HEADER;
	memcpy(h->rx_buf + h->rx_pos, pkt + CTAPHID_CONT_HEADER, take);
	h->rx_pos += take;
	h->rx_seq = (uint8_t)(seq + 1);

	if (h->rx_pos >= h->rx_len) {
		h->rx_ready = 0;
		dispatch_message(h);
		return emit_tx(h, out, max_out);
	}
	return 0;
}