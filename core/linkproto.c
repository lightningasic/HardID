/*
 * HardID Hardware Wallet — host<->device link protocol
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "linkproto.h"
#include <string.h>

/* CRC-16/CCITT-FALSE: poly 0x1021, init 0xFFFF, MSB-first, no reflection,
 * no final xor. Matches the 0x186F style check used in serial bootloaders so
 * the frame is portable to a host library. */
uint16_t hd_link_crc(const uint8_t *data, size_t len)
{
	uint16_t crc = HD_LINK_CRC_INIT;
	for (size_t i = 0; i < len; i++) {
		crc ^= (uint16_t)(data[i] << 8);
		for (int b = 0; b < 8; b++) {
			crc = (crc & 0x8000u) ? (uint16_t)((crc << 1) ^ 0x1021u)
			                      : (uint16_t)(crc << 1);
		}
	}
	return crc;
}

static int frame(uint8_t type, uint16_t seq, int32_t rc,
                 const uint8_t *payload, size_t plen,
                 uint8_t *out, size_t out_max, int with_rc)
{
	/* Replies carry their rc as a 4-byte prefix inside the payload so the
	 * frame layout is identical for both directions (payload always begins
	 * at HD_LINK_HDR_LEN). */
	uint8_t rp[4 + 512];
	size_t use = 0;
	if (with_rc) {
		if (HD_LINK_HDR_LEN + 4u + plen + 2u > sizeof rp)
			return -1;
		rp[0] = (uint8_t)((uint32_t)rc >> 24);
		rp[1] = (uint8_t)(rc >> 16);
		rp[2] = (uint8_t)(rc >> 8);
		rp[3] = (uint8_t)(rc & 0xFFu);
		use = 4u + plen;
		if (plen) memcpy(rp + 4, payload, plen);
		payload = rp;
		plen = use;
	}

	if (plen > 0xFFFFu)
		return -1;
	size_t total = HD_LINK_HDR_LEN + plen + 2u;
	if (total > out_max || total > HD_LINK_MAX_FRAME)
		return -1;

	size_t n = 0;
	out[n++] = HD_LINK_MAGIC;
	out[n++] = HD_LINK_VER;
	out[n++] = type;
	out[n++] = 0;                              /* flags */
	out[n++] = (uint8_t)(plen >> 8);           /* length (big-endian) */
	out[n++] = (uint8_t)(plen & 0xFFu);
	out[n++] = (uint8_t)seq;
	out[n++] = 0;                              /* reserved (keeps hdr = 8B) */

	if (plen) {
		memcpy(out + n, payload, plen);
		n += plen;
	}

	uint16_t crc = hd_link_crc(out, n);
	out[n++] = (uint8_t)(crc >> 8);
	out[n++] = (uint8_t)(crc & 0xFFu);
	return (int)n;
}

int hd_link_frame_cmd(uint8_t type, uint16_t seq,
                      const uint8_t *payload, size_t plen,
                      uint8_t *out, size_t out_max)
{
	return frame(type, seq, 0, payload, plen, out, out_max, 0);
}

int hd_link_frame_reply(uint8_t type, uint16_t seq, int32_t rc,
                        const uint8_t *payload, size_t plen,
                        uint8_t *out, size_t out_max)
{
	return frame(type, seq, rc, payload, plen, out, out_max, 1);
}

int hd_link_parse(const uint8_t *buf, size_t buf_len,
                  uint8_t *type, uint16_t *seq,
                  const uint8_t **payload, size_t *plen)
{
	if (!buf || !type || !seq)
		return -1;
	if (buf_len < HD_LINK_HDR_LEN)
		return -1;
	if (buf[0] != HD_LINK_MAGIC || buf[1] != HD_LINK_VER)
		return -1;

	size_t pl = ((size_t)buf[4] << 8) | buf[5];
	size_t total = HD_LINK_HDR_LEN + pl + 2u;
	if (total > buf_len)
		return -1;

	/* CRC over magic..payload; trailing 2 bytes are the crc itself */
	uint16_t stored = (uint16_t)((buf[total - 2] << 8) | buf[total - 1]);
	uint16_t calc = hd_link_crc(buf, total - 2);
	if (calc != stored)
		return -1;

	*type = buf[2];
	*seq = (uint16_t)buf[6];
	if (payload) *payload = buf + HD_LINK_HDR_LEN;
	if (plen) *plen = pl;
	return 0;
}