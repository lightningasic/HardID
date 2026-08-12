/*
 * HardID Hardware Wallet — CTAP2 command parsing / dispatch
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Parses CTAP2 CBOR request messages, dispatches to core/fido_core.c and
 * produces the CTAP2 response message (status byte + CBOR payload).
 * Wire format for CTAPHID_CBOR (CTAP2 §11.2.9.1.2):
 *   request : cmd(1) || CBOR(cmd-specific)
 *   response: status(1) || CBOR(success payload)
 * Parsing is bounded (core/cbor.c) per the design's attack-surface policy.
 */

#include "ctap2.h"
#include "cbor.h"
#include "fido_core.h"
#include "hkdf.h"
#include "sha256.h"
#include <string.h>

/* ---- request field keys (CTAP2 §6.1/§6.2) ---- */
#define K_CLIENT_DATA_HASH 0x01
#define K_RP               0x02
#define K_USER             0x03
#define K_PUBKEY_CRED_PARAMS 0x04
#define K_EXCLUDE_LIST     0x05
#define K_EXTENSIONS       0x06
#define K_OPTIONS          0x07

/* nested map keys */
#define K_RP_ID   0x01
#define K_RP_NAME 0x02
#define K_USER_ID 0x01
#define K_USER_NAME 0x02
#define K_USER_DISPLAY 0x03

#define K_PKCP_ALG  0x03
#define K_PKCP_TYPE 0x01

/* getAssertion keys */
#define K_GA_RPID           0x01
#define K_GA_CLIENT_DATA    0x02
#define K_GA_ALLOW_LIST     0x03
#define K_GA_OPTIONS        0x05
#define K_CRED_ID           0x01
#define K_CRED_TYPE         0x02

#define MAX_TEXT_LEN 128

/* Read required 32-byte byte string field. */
static int req_client_data_hash(cbor_reader_t *r, uint8_t out[32])
{
	const uint8_t *p;
	size_t n;
	int rc = cbor_read_bytes_head(r, &p, &n);
	if (rc != CBOR_OK)
		return rc;
	if (n != 32)
		return CTAP2_ERR_INVALID_CBOR;
	memcpy(out, p, 32);
	return CBOR_OK;
}

static int req_text(cbor_reader_t *r, char *out, size_t out_cap)
{
	const uint8_t *p;
	size_t n;
	int rc = cbor_read_text_head(r, &p, &n);
	if (rc != CBOR_OK)
		return rc;
	if (n + 1 > out_cap)
		return CTAP2_ERR_INVALID_CBOR;
	memcpy(out, p, n);
	out[n] = '\0';
	return CBOR_OK;
}

/* Parse rp map {1:id, 2:name}. */
static int parse_rp(cbor_reader_t *r, char *rp_id, size_t rp_id_cap,
                    char *rp_name, size_t rp_name_cap)
{
	size_t members;
	int rc = cbor_read_map_head(r, &members);
	if (rc != CBOR_OK)
		return rc;
	rp_id[0] = '\0';
	rp_name[0] = '\0';
	for (size_t i = 0; i < members; i++) {
		uint64_t key;
		if ((rc = cbor_read_uint(r, &key)) != CBOR_OK)
			return rc;
		if (key == K_RP_ID) {
			if ((rc = req_text(r, rp_id, rp_id_cap)) != CBOR_OK)
				return rc;
		} else if (key == K_RP_NAME) {
			if ((rc = req_text(r, rp_name, rp_name_cap)) != CBOR_OK)
				return rc;
		} else if ((rc = cbor_skip(r)) != CBOR_OK) {
			return rc;
		}
	}
	if (rp_id[0] == '\0')
		return CTAP2_ERR_MISSING_PARAMETER;
	return CBOR_OK;
}

/* Parse the (required) pubKeyCredParams array; ensure it advertises
 * alg -7 (ES256) so we answer UNSUPPORTED_ALGORITHM otherwise (design §3.3,
 * and CTAP2 requires scanning all entries). */
static int parse_pkcp(cbor_reader_t *r, bool *has_es256)
{
	size_t n;
	int rc = cbor_read_array_head(r, &n);
	if (rc != CBOR_OK)
		return rc;
	*has_es256 = false;
	for (size_t i = 0; i < n; i++) {
		size_t members;
		if ((rc = cbor_read_map_head(r, &members)) != CBOR_OK)
			return rc;
		int64_t alg = 0;
		bool seen_alg = false;
		for (size_t j = 0; j < members; j++) {
			uint64_t key;
			if ((rc = cbor_read_uint(r, &key)) != CBOR_OK)
				return rc;
			if (key == K_PKCP_ALG) {
				if ((rc = cbor_read_int(r, &alg)) != CBOR_OK)
					return rc;
				seen_alg = true;
			} else if ((rc = cbor_skip(r)) != CBOR_OK) {
				return rc;
			}
		}
		if (seen_alg && alg == COSE_ALG_ES256)
			*has_es256 = true;
	}
	if (n == 0)
		return CTAP2_ERR_MISSING_PARAMETER;
	return CBOR_OK;
}

/* Parse the options map (keys: 0x01 up, 0x02 uv). Missing "up" defaults to
 * true (CTAP2 §6.1.9: user presence is implied when not requested). "uv"
 * is never honored in v1 (decision A2) but must be tolerated/validated. */
static int parse_options(cbor_reader_t *r, bool *up)
{
	size_t members;
	int rc = cbor_read_map_head(r, &members);
	if (rc != CBOR_OK)
		return rc;
	if (up)
		*up = true;   /* default: presence required */
	for (size_t i = 0; i < members; i++) {
		uint64_t key;
		if ((rc = cbor_read_uint(r, &key)) != CBOR_OK)
			return rc;
		bool v = false;
		if ((rc = cbor_read_bool(r, &v)) != CBOR_OK)
			return rc;
		if (key == 0x01 && up) {
			if (!v)
				*up = false;   /* explicit up:false */
		}
		/* key 0x02 (uv) accepted and ignored (A2) */
	}
	return CBOR_OK;
}

/* Parse the user map (skipped beyond rp_id in v1). */
static int parse_user(cbor_reader_t *r, char *name, size_t name_cap)
{
	size_t members;
	int rc = cbor_read_map_head(r, &members);
	if (rc != CBOR_OK)
		return rc;
	name[0] = '\0';
	for (size_t i = 0; i < members; i++) {
		uint64_t key;
		if ((rc = cbor_read_uint(r, &key)) != CBOR_OK)
			return rc;
		if (key == K_USER_NAME && name_cap > 1) {
			if ((rc = req_text(r, name, name_cap)) != CBOR_OK)
				return rc;
		} else if ((rc = cbor_skip(r)) != CBOR_OK) {
			return rc;
		}
	}
	return CBOR_OK;
}

static int handle_make_credential(const uint8_t *req, size_t req_len,
                                  uint8_t *resp, size_t resp_cap,
                                  size_t *resp_len)
{
	cbor_reader_t rd;
	cbor_reader_init(&rd, req, req_len, 128);
	size_t members;
	int rc = cbor_read_map_head(&rd, &members);
	if (rc != CBOR_OK)
		return rc;

	fido_make_cred_req_t mcr;
	memset(&mcr, 0, sizeof mcr);
	mcr.up_required = true;   /* CTAP2 §6.1.9: presence implied by default */
	char rp_id[MAX_TEXT_LEN], rp_name[MAX_TEXT_LEN], user_name[MAX_TEXT_LEN];

	bool have_cdh = false, have_pkcp = false, have_es256 = false;
	for (size_t i = 0; i < members; i++) {
		uint64_t key;
		if ((rc = cbor_read_uint(&rd, &key)) != CBOR_OK)
			return rc;
		switch (key) {
		case K_CLIENT_DATA_HASH:
			if ((rc = req_client_data_hash(&rd, mcr.client_data_hash)) != CBOR_OK)
				return rc;
			have_cdh = true;
			break;
		case K_RP:
			if ((rc = parse_rp(&rd, rp_id, sizeof rp_id,
			                   rp_name, sizeof rp_name)) != CBOR_OK)
				return rc;
			break;
		case K_USER:
			if ((rc = parse_user(&rd, user_name, sizeof user_name)) != CBOR_OK)
				return rc;
			break;
		case K_PUBKEY_CRED_PARAMS:
			if ((rc = parse_pkcp(&rd, &have_es256)) != CBOR_OK)
				return rc;
			have_pkcp = true;
			break;
		case K_EXCLUDE_LIST:
		case K_EXTENSIONS:
			/* v1: parse (validate) but treat as no-op. */
			if ((rc = cbor_skip(&rd)) != CBOR_OK)
				return rc;
			break;
		case K_OPTIONS:
			/* options.up defaults true (CTAP2 §6.1.9); parse so an
			 * explicit up:false (probe) really reports absent UP. */
			if ((rc = parse_options(&rd, &mcr.up_required)) != CBOR_OK)
				return rc;
			break;
		default:
			/* unknown member: MUST be tolerated (CTAP2 §6.1) */
			if ((rc = cbor_skip(&rd)) != CBOR_OK)
				return rc;
			break;
		}
	}

	if (!have_cdh)
		return CTAP2_ERR_MISSING_PARAMETER;
	if (!have_pkcp)
		return CTAP2_ERR_MISSING_PARAMETER;
	if (!have_es256)
		return CTAP2_ERR_UNSUPPORTED_ALGORITHM;

	mcr.rp_name = rp_name[0] ? rp_name : rp_id;
	mcr.user_name = user_name[0] ? user_name : NULL;
	os_sha256((const uint8_t *)rp_id, strlen(rp_id), mcr.rp_id_hash);

	int st = fido_make_credential(&mcr, resp, resp_cap, resp_len);
	return st;
}

static int handle_get_assertion(const uint8_t *req, size_t req_len,
                                uint8_t *resp, size_t resp_cap,
                                size_t *resp_len)
{
	cbor_reader_t rd;
	cbor_reader_init(&rd, req, req_len, 128);
	size_t members;
	int rc = cbor_read_map_head(&rd, &members);
	if (rc != CBOR_OK)
		return rc;

	fido_get_assert_req_t gar;
	memset(&gar, 0, sizeof gar);
	gar.up_required = true;   /* CTAP2 §6.2: presence implied by default */
	char rp_id[MAX_TEXT_LEN];

	bool have_rpid = false, have_cdh = false;
	for (size_t i = 0; i < members; i++) {
		uint64_t key;
		if ((rc = cbor_read_uint(&rd, &key)) != CBOR_OK)
			return rc;
		switch (key) {
		case K_GA_RPID:
			if ((rc = req_text(&rd, rp_id, sizeof rp_id)) != CBOR_OK)
				return rc;
			have_rpid = true;
			break;
		case K_GA_CLIENT_DATA:
			if ((rc = req_client_data_hash(&rd, gar.client_data_hash)) != CBOR_OK)
				return rc;
			have_cdh = true;
			break;
		case K_GA_ALLOW_LIST: {
			/* v1: take the first entry {1:id,2:type}. */
			size_t n;
			if ((rc = cbor_read_array_head(&rd, &n)) != CBOR_OK)
				return rc;
			if (n > 0) {
				size_t mm;
				if ((rc = cbor_read_map_head(&rd, &mm)) != CBOR_OK)
					return rc;
				for (size_t j = 0; j < mm; j++) {
					uint64_t k;
					if ((rc = cbor_read_uint(&rd, &k)) != CBOR_OK)
						return rc;
					if (k == K_CRED_ID) {
						size_t clen = sizeof gar.allowlist_credid;
						uint8_t idbuf[sizeof gar.allowlist_credid];
						if ((rc = cbor_read_bytes(&rd, idbuf, &clen)) != CBOR_OK)
							return rc;
						memcpy(gar.allowlist_credid, idbuf, clen);
						gar.allowlist_credid_len = clen;
					} else if ((rc = cbor_skip(&rd)) != CBOR_OK) {
						return rc;
					}
				}
				/* skip remaining allowlist entries */
				for (size_t j = 1; j < n; j++)
					if ((rc = cbor_skip(&rd)) != CBOR_OK)
						return rc;
			}
			break;
		}
		case K_GA_OPTIONS:
			/* options.up defaults true; honor explicit up:false. */
			if ((rc = parse_options(&rd, &gar.up_required)) != CBOR_OK)
				return rc;
			break;
		case K_EXTENSIONS:
			if ((rc = cbor_skip(&rd)) != CBOR_OK)
				return rc;
			break;
		default:
			if ((rc = cbor_skip(&rd)) != CBOR_OK)
				return rc;
			break;
		}
	}

	if (!have_rpid)
		return CTAP2_ERR_MISSING_PARAMETER;
	if (!have_cdh)
		return CTAP2_ERR_MISSING_PARAMETER;
	if (gar.allowlist_credid_len == 0)
		return CTAP2_ERR_NO_CREDENTIALS;

	gar.rp_name = rp_id;
	os_sha256((const uint8_t *)rp_id, strlen(rp_id), gar.rp_id_hash);

	int st = fido_get_assertion(&gar, resp, resp_cap, resp_len);
	return st;
}

/* ---- public entry ---- */
int ctap2_handle(const uint8_t *msg, size_t len,
                 uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	if (len < 1)
		return CTAP1_ERR_INVALID_LENGTH;
	uint8_t cmd = msg[0];
	const uint8_t *req = msg + 1;
	size_t req_len = len - 1;

	/* GetInfo takes no input parameters; tolerate a trailing empty map. */
	if (cmd == CTAP2_CMD_GET_INFO) {
		int st = fido_getinfo(resp, resp_cap, resp_len);
		return st;
	}

	int st;
	switch (cmd) {
	case CTAP2_CMD_MAKE_CREDENTIAL:
		st = handle_make_credential(req, req_len, resp, resp_cap, resp_len);
		break;
	case CTAP2_CMD_GET_ASSERTION:
		st = handle_get_assertion(req, req_len, resp, resp_cap, resp_len);
		break;
	case CTAP2_CMD_CLIENT_PIN:
	case CTAP2_CMD_GET_NEXT_ASSERT:
	case CTAP2_CMD_CONFIG:
		st = CTAP2_ERR_UNSUPPORTED_OPTION;   /* explicitly not supported (v1) */
		break;
	case CTAP2_CMD_RESET:
		st = CTAP2_ERR_OPERATION_DENIED;      /* gated to the 10s window at UI
		                                         layer; see design §3.1/§4.4 */
		break;
	default:
		st = CTAP1_ERR_INVALID_COMMAND;
		break;
	}

	return st;
}