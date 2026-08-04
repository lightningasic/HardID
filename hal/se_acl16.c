/*
 * HardID Hardware Wallet — ACL16 secure-element driver (APDU layer)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "se_acl16.h"
#include "se_acl16_opcodes.h"
#include "../core/secure_zero.h"
#include <string.h>

#define ACL16_MAX_APDU   260   /* 5 hdr + 255 data */
#define ACL16_MAX_RESP   260

void se_acl16_init_ctx(se_acl16_t *ctx, se_chip chip)
{
	ctx->chip = chip;
	ctx->default_timeout_ms = 1000;
}

/* Map an APDU status word to an se_driver-style error code (negative). */
static int sw_to_err(uint16_t sw)
{
	switch (sw) {
	case SE_SW_OK:          return 0;
	case SE_SW_AUTH_FAILED: return -2;   /* SE_ERR_AUTH */
	case SE_SW_LOCKED:      return -3;   /* SE_ERR_LOCKED */
	case SE_SW_NOT_INIT:    return -5;   /* SE_ERR_STATE */
	case SE_SW_WRONG_LENGTH:
	case SE_SW_WRONG_DATA:  return -4;   /* SE_ERR_PARAM */
	default:                return -6;   /* SE_ERR_INTERNAL */
	}
}

int se_acl16_apdu(se_acl16_t *ctx,
                  uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                  const uint8_t *data, size_t data_len,
                  uint8_t *resp, size_t *resp_len, size_t resp_max)
{
	const se_transport_t *t = se_transport_get();
	uint8_t frame[ACL16_MAX_APDU];
	uint8_t rbuf[ACL16_MAX_RESP];
	size_t n = 0;
	int rc;

	if (!t || data_len > 255)
		return SE_T_ERR_PARAM;

	/* build command APDU: CLA INS P1 P2 [Lc data] [Le=0x00 => max] */
	frame[n++] = cla;
	frame[n++] = ins;
	frame[n++] = p1;
	frame[n++] = p2;
	if (data && data_len) {
		frame[n++] = (uint8_t)data_len;
		memcpy(frame + n, data, data_len);
		n += data_len;
	}
	frame[n++] = 0x00;   /* Le */

	t->cs(ctx->chip, true);
	rc = t->write(frame, n);
	if (rc != SE_T_OK) {
		t->cs(ctx->chip, false);
		return SE_T_ERR_IO;
	}

	/* read response: [data] SW1 SW2. Keep reading until the transport
	 * reports a timeout (no more bytes) — never stop after a partial read. */
	size_t got = 0;
	for (;;) {
		if (got >= sizeof rbuf) {
			t->cs(ctx->chip, false);
			return SE_T_ERR_IO;    /* response larger than buffer */
		}
		int r = t->read(rbuf + got, sizeof rbuf - got, ctx->default_timeout_ms);
		if (r < 0) {
			t->cs(ctx->chip, false);
			return SE_T_ERR_IO;
		}
		if (r == 0)
			break;               /* timeout => no more bytes */
		got += (size_t)r;
	}
	t->cs(ctx->chip, false);

	if (got < 2)
		return SE_T_ERR_TIMEOUT;

	uint16_t sw = ((uint16_t)rbuf[got - 2] << 8) | rbuf[got - 1];
	size_t dlen = got - 2;
	if (resp && resp_len) {
		size_t take = dlen < resp_max ? dlen : resp_max;
		memcpy(resp, rbuf, take);
		*resp_len = take;
	}
	os_secure_bzero(rbuf, sizeof rbuf);
	return sw_to_err(sw);
}

/* ---- high-level ops ---- */

int se_acl16_get_random(se_acl16_t *ctx, uint8_t *buf, size_t len)
{
	/* fetch in chunks of up to 255 bytes */
	size_t off = 0;
	while (off < len) {
		size_t want = len - off;
		if (want > 255) want = 255;
		uint8_t p1 = (uint8_t)want;
		size_t rlen = 0;
		int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_GET_RANDOM,
		                       p1, 0x00, NULL, 0, buf + off, &rlen, want);
		if (rc != 0)
			return rc;
		off += rlen > 0 ? rlen : want;
	}
	return 0;
}

int se_acl16_store_seed(se_acl16_t *ctx, const uint8_t *seed32)
{
	uint8_t rbuf[8]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_STORE_SEED,
	                       0x00, 0x00, seed32, 32, rbuf, &rlen, sizeof rbuf);
	os_secure_bzero(rbuf, sizeof rbuf);
	return rc;
}

int se_acl16_is_initialized(se_acl16_t *ctx, bool *initialized)
{
	uint8_t rbuf[4]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_IS_INIT,
	                       0x00, 0x00, NULL, 0, rbuf, &rlen, sizeof rbuf);
	if (rc != 0)
		return rc;
	*initialized = (rlen > 0 && rbuf[0] != 0);
	return 0;
}

int se_acl16_sign_digest(se_acl16_t *ctx, const uint32_t *path, size_t path_len,
                         const uint8_t *digest32, uint8_t *sig64, uint8_t *recid)
{
	/* data: path_len(1) || path_be32[] || digest32 */
	uint8_t data[1 + 15 * 4 + 32];
	size_t n = 0;
	if (path_len > 15)
		return -4;
	data[n++] = (uint8_t)path_len;
	for (size_t i = 0; i < path_len; i++) {
		data[n++] = (uint8_t)(path[i] >> 24);
		data[n++] = (uint8_t)(path[i] >> 16);
		data[n++] = (uint8_t)(path[i] >> 8);
		data[n++] = (uint8_t)(path[i]);
	}
	memcpy(data + n, digest32, 32);
	n += 32;

	uint8_t rbuf[65]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_SIGN,
	                       ACL16_P1_CURVE_SECP256K1, 0x00,
	                       data, n, rbuf, &rlen, sizeof rbuf);
	os_secure_bzero(data, sizeof data);
	if (rc != 0)
		return rc;
	if (rlen < 64)
		return -6;
	memcpy(sig64, rbuf, 64);
	if (recid)
		*recid = (rlen > 64) ? rbuf[64] : 0;
	os_secure_bzero(rbuf, sizeof rbuf);
	return 0;
}

int se_acl16_get_xpub(se_acl16_t *ctx, const uint32_t *path, size_t path_len,
                      char *xpub_out, size_t xpub_max)
{
	uint8_t data[1 + 15 * 4];
	size_t n = 0;
	if (path_len > 15)
		return -4;
	data[n++] = (uint8_t)path_len;
	for (size_t i = 0; i < path_len; i++) {
		data[n++] = (uint8_t)(path[i] >> 24);
		data[n++] = (uint8_t)(path[i] >> 16);
		data[n++] = (uint8_t)(path[i] >> 8);
		data[n++] = (uint8_t)(path[i]);
	}
	uint8_t rbuf[128]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_GET_XPUB,
	                       ACL16_P1_CURVE_SECP256K1, 0x00,
	                       data, n, rbuf, &rlen, sizeof rbuf);
	os_secure_bzero(data, sizeof data);
	if (rc != 0)
		return rc;
	if (rlen == 0 || rlen >= xpub_max)
		return -6;
	memcpy(xpub_out, rbuf, rlen);
	xpub_out[rlen] = 0;
	os_secure_bzero(rbuf, sizeof rbuf);
	return 0;
}

int se_acl16_verify_pin(se_acl16_t *ctx, const uint8_t *pin, size_t len,
                        uint32_t *wait_seconds, bool *is_duress)
{
	uint8_t rbuf[8]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_VERIFY_PIN,
	                       0x00, 0x00, pin, len, rbuf, &rlen, sizeof rbuf);
	if (rc == -3 && wait_seconds) {
		/* locked: SE returns remaining wait seconds in rbuf (4-byte LE) */
		*wait_seconds = (rlen >= 4)
			? ((uint32_t)rbuf[0] | ((uint32_t)rbuf[1] << 8) |
			   ((uint32_t)rbuf[2] << 16) | ((uint32_t)rbuf[3] << 24))
			: 0;
	}
	if (rc == 0 && is_duress)
		*is_duress = (rlen > 0 && rbuf[0] != 0);
	os_secure_bzero(rbuf, sizeof rbuf);
	return rc;
}

int se_acl16_policy_authorize(se_acl16_t *ctx, uint32_t policy_id, uint64_t amount)
{
	uint8_t data[12];
	for (int i = 0; i < 4; i++) data[i] = (uint8_t)(policy_id >> (24 - i * 8));
	for (int i = 0; i < 8; i++) data[4 + i] = (uint8_t)(amount >> (56 - i * 8));
	uint8_t rbuf[4]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_POLICY_AUTH,
	                       0x00, 0x00, data, sizeof data, rbuf, &rlen, sizeof rbuf);
	os_secure_bzero(data, sizeof data);
	os_secure_bzero(rbuf, sizeof rbuf);
	return rc;   /* 0 = auto-approved, -2 (AUTH) = manual confirm required */
}

int se_acl16_monotonic_read(se_acl16_t *ctx, uint32_t *counter)
{
	uint8_t rbuf[4]; size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_MONO_READ,
	                       0x00, 0x00, NULL, 0, rbuf, &rlen, sizeof rbuf);
	if (rc != 0)
		return rc;
	if (rlen < 4)
		return -6;
	*counter = (uint32_t)rbuf[0] | ((uint32_t)rbuf[1] << 8) |
	           ((uint32_t)rbuf[2] << 16) | ((uint32_t)rbuf[3] << 24);
	return 0;
}

int se_acl16_monotonic_increment(se_acl16_t *ctx)
{
	uint8_t rbuf[4]; size_t rlen = 0;
	return se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_MONO_INC,
	                     0x00, 0x00, NULL, 0, rbuf, &rlen, sizeof rbuf);
}

int se_acl16_attest(se_acl16_t *ctx, const uint8_t *challenge32,
                    uint8_t *response, size_t *resp_len)
{
	size_t rlen = 0;
	int rc = se_acl16_apdu(ctx, ACL16_CLA, ACL16_INS_ATTEST,
	                       0x00, 0x00, challenge32, 32,
	                       response, &rlen, *resp_len);
	if (rc == 0)
		*resp_len = rlen;
	return rc;
}
