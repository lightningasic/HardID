/*
 * HardID Hardware Wallet — FIDO core (credential lifecycle)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * makeCredential / getAssertion / GetInfo. Design doc 09 §4/§5/§6.
 * All key material lives in the SE; this module assembles the public
 * authenticatorData + attestationObject and applies the user-presence
 * confirm gate (design A3: never sign without confirmation).
 */

#include "fido_core.h"
#include "cbor.h"
#include "hkdf.h"
#include "sha256.h"
#include "secure_zero.h"
#include <string.h>

/* Product AAGUID (design A1): fixed at build time, 16 bytes. */
const uint8_t fido_aaguid[FIDO_AAGUID_LEN] = {
	0x68, 0x61, 0x72, 0x64, 0x69, 0x64, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
};

static fido_confirm_fn confirm_handler;

void fido_set_confirm_handler(fido_confirm_fn fn)
{
	confirm_handler = fn;
}

static const se_driver_t *se(void)
{
	return se_active();
}

/* Attach the SE-backed make/sign interfaces if present; NULL when the
 * backend has no P-256 yet (design A5). */
static bool fido_se_available(void)
{
	return se()->fido_cred_make != NULL && se()->fido_cred_sign != NULL &&
	       se()->fido_signcount_read != NULL;
}

/* ---- GetInfo (design §3.2) ---- */
int fido_getinfo(uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	cbor_writer_t w;
	cbor_writer_init(&w, resp, resp_cap);
	if (cbor_write_map_head(&w, 10) != CBOR_OK)
		return CTAP1_ERR_OTHER;

	/* 0x01 versions: ["FIDO_2_0"] */
	if (cbor_write_uint(&w, 1) || cbor_write_array_head(&w, 1) ||
	    cbor_write_text(&w, "FIDO_2_0"))
		return CTAP1_ERR_OTHER;
	/* 0x02 extensions: [] */
	if (cbor_write_uint(&w, 2) || cbor_write_array_head(&w, 0))
		return CTAP1_ERR_OTHER;
	/* 0x03 aaguid */
	if (cbor_write_uint(&w, 3) || cbor_write_bytes(&w, fido_aaguid, 16))
		return CTAP1_ERR_OTHER;
	/* 0x04 options: rk=false, up=true, uv=false, clientPin=false */
	if (cbor_write_uint(&w, 4) || cbor_write_map_head(&w, 4) ||
	    cbor_write_text(&w, "rk") || cbor_write_bool(&w, false) ||
	    cbor_write_text(&w, "up") || cbor_write_bool(&w, true) ||
	    cbor_write_text(&w, "uv") || cbor_write_bool(&w, false) ||
	    cbor_write_text(&w, "clientPin") || cbor_write_bool(&w, false))
		return CTAP1_ERR_OTHER;
	/* 0x05 maxMsgSize */
	if (cbor_write_uint(&w, 5) || cbor_write_uint(&w, FIDO_GETINFO_MAX_MSG_SIZE))
		return CTAP1_ERR_OTHER;
	/* 0x06 pinUvAuthProtocols: [1] */
	if (cbor_write_uint(&w, 6) || cbor_write_array_head(&w, 1) ||
	    cbor_write_uint(&w, 1))
		return CTAP1_ERR_OTHER;
	/* 0x07 maxCredentialCountInList */
	if (cbor_write_uint(&w, 7) || cbor_write_uint(&w, FIDO_GETINFO_MAX_CRED_COUNT))
		return CTAP1_ERR_OTHER;
	/* 0x08 maxCredentialIdLength */
	if (cbor_write_uint(&w, 8) || cbor_write_uint(&w, FIDO_GETINFO_MAX_CRED_ID_LEN))
		return CTAP1_ERR_OTHER;
	/* 0x09 transports: ["usb"] */
	if (cbor_write_uint(&w, 9) || cbor_write_array_head(&w, 1) ||
	    cbor_write_text(&w, "usb"))
		return CTAP1_ERR_OTHER;
	/* 0x0A algorithms: [{"type":"public-key","alg":-7}] */
	if (cbor_write_uint(&w, 10) || cbor_write_array_head(&w, 1) ||
	    cbor_write_map_head(&w, 2) ||
	    cbor_write_text(&w, "alg") || cbor_write_int(&w, COSE_ALG_ES256) ||
	    cbor_write_text(&w, "type") || cbor_write_text(&w, "public-key"))
		return CTAP1_ERR_OTHER;

	*resp_len = w.len;
	return CTAP2_OK;
}

/* ---- COSE EC2 public key (uncompressed 65B -> CBOR map) ---- */
static int write_cose_pubkey(cbor_writer_t *w, const uint8_t pub65[65])
{
	if (pub65[0] != 0x04)
		return CBOR_ERR_TYPE;
	/* COSE EC2 public key (RFC 8152 §13.1.1):
	 * {1:kty=EC2, 3:alg=ES256, -1:crv=P-256, -2:x, -3:y}.
	 * Canonical (RFC 8949 §4.2.1) ascending key order: 1, 3, -1, -2, -3. */
	if (cbor_write_map_head(w, 5))
		return CBOR_ERR_OVERFLOW;
	if (cbor_write_uint(w, 1) || cbor_write_uint(w, COSE_KTY_EC2))
		return CBOR_ERR_OVERFLOW;
	if (cbor_write_uint(w, 3) || cbor_write_int(w, COSE_ALG_ES256))
		return CBOR_ERR_OVERFLOW;
	if (cbor_write_int(w, -1) || cbor_write_uint(w, COSE_CRV_P256))
		return CBOR_ERR_OVERFLOW;
	if (cbor_write_int(w, -2) || cbor_write_bytes(w, pub65 + 1, 32))
		return CBOR_ERR_OVERFLOW;
	if (cbor_write_int(w, -3) || cbor_write_bytes(w, pub65 + 33, 32))
		return CBOR_ERR_OVERFLOW;
	return CBOR_OK;
}

/* Build authData with attested credential data:
 *   rpIdHash(32) || flags(1) || signCount(4 BE) ||
 *   aaguid(16) || credIdLen(2 BE) || credID || cosePubkey
 * Returns bytes written to out, or -1. */
static int build_attested_authdata(const uint8_t rp_hash32[32],
                                   uint8_t flags,
                                   const uint8_t zero_cnt[4],
                                   const uint8_t credid[FIDO_CREDID_LEN],
                                   const uint8_t pub65[65],
                                   uint8_t *out, size_t out_cap)
{
	cbor_writer_t cose;
	uint8_t cosebuf[128];
	cbor_writer_init(&cose, cosebuf, sizeof cosebuf);
	if (write_cose_pubkey(&cose, pub65) != CBOR_OK)
		return -1;

	size_t n = FIDO_AT_HEADER_LEN + FIDO_AAGUID_LEN + 2 +
	           FIDO_CREDID_LEN + cose.len;
	if (n > out_cap)
		return -1;
	memcpy(out, rp_hash32, 32);
	out[32] = flags;
	memcpy(out + 33, zero_cnt, 4);
	memcpy(out + 37, fido_aaguid, 16);
	out[53] = (uint8_t)(FIDO_CREDID_LEN >> 8);
	out[54] = (uint8_t)FIDO_CREDID_LEN;
	memcpy(out + 55, credid, FIDO_CREDID_LEN);
	memcpy(out + 55 + FIDO_CREDID_LEN, cosebuf, cose.len);
	return (int)n;
}

/* ---- makeCredential ---- */
int fido_make_credential(const fido_make_cred_req_t *req,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	if (!fido_se_available())
		return CTAP2_ERR_UNSUPPORTED_ALGORITHM;  /* design A5 */

	/* excludeCredentials (CTAP2 §5.1.2): if the RP lists a credential we
	 * already hold for this RP, report CREDENTIAL_EXCLUDED so the browser
	 * can prompt the user instead of silently registering a duplicate
	 * (GitHub second-add flow). Checked before the user-presence dialog. */
	for (size_t i = 0; i < req->exclude_count; i++)
		if (se()->fido_cred_exists(req->exclude_credid[i],
		                           req->rp_id_hash) == SE_OK)
			return CTAP2_ERR_CREDENTIAL_EXCLUDED;

	/* User presence confirm (design A2/A3). Default handler denies. */
	if (confirm_handler && !confirm_handler(req->rp_name, true))
		return CTAP2_ERR_OPERATION_DENIED;
	if (!confirm_handler)
		return CTAP2_ERR_OPERATION_DENIED;

	uint8_t credid[FIDO_CREDID_LEN];
	uint8_t pub65[65];
	int rc = se()->fido_cred_make(req->rp_id_hash, pub65, credid);
	if (rc != SE_OK)
		return CTAP2_ERR_PROCESSING;

	/* authData: flags AT|UP, signCount 0 */
	uint8_t flags = FIDO_AT_FLAG_AT;
	if (req->up_required)
		flags |= FIDO_AT_FLAG_UP;
	static const uint8_t zero_cnt[4] = {0, 0, 0, 0};
	uint8_t authdata[FIDO_AT_HEADER_LEN + FIDO_AAGUID_LEN + 2 +
	                  FIDO_CREDID_LEN + 128];
	int adlen = build_attested_authdata(req->rp_id_hash, flags, zero_cnt,
	                                    credid, pub65,
	                                    authdata, sizeof authdata);
	if (adlen < 0)
		return CTAP2_ERR_PROCESSING;

	/* attestationObject = {fmt:"none", authData, attStmt:{}} (design A1) */
	cbor_writer_t w;
	cbor_writer_init(&w, resp, resp_cap);
	if (cbor_write_map_head(&w, 3) ||
	    cbor_write_uint(&w, 1) || cbor_write_text(&w, "none") ||
	    cbor_write_uint(&w, 2) || cbor_write_bytes(&w, authdata, (size_t)adlen) ||
	    cbor_write_uint(&w, 3) || cbor_write_map_head(&w, 0))
		return CTAP1_ERR_OTHER;
	*resp_len = w.len;
	return CTAP2_OK;
}

/* ---- getAssertion ---- */

/* Encode an ES256 (P-256) signature from raw r||s (64 bytes) into an
 * ASN.1 DER Ecdsa-Sig-Value. WebAuthn §6.5.5: for COSEAlgorithmIdentifier
 * -7 (ES256) the signature MUST be DER-encoded. */
static void der_encode_ecdsa(const uint8_t sig64[64], uint8_t *out,
                             size_t *out_len)
{
	const uint8_t *r = sig64, *s = sig64 + 32;
	size_t rlen = 32, slen = 32;
	uint8_t rbuf[33], sbuf[33];

	while (rlen > 1 && *r == 0) { r++; rlen--; }
	while (slen > 1 && *s == 0) { s++; slen--; }
	if (*r & 0x80) { rbuf[0] = 0; memcpy(rbuf + 1, r, rlen); r = rbuf; rlen++; }
	if (*s & 0x80) { sbuf[0] = 0; memcpy(sbuf + 1, s, slen); s = sbuf; slen++; }

	size_t body = 2 + rlen + 2 + slen;
	out[0] = 0x30;
	out[1] = (uint8_t)body;
	out[2] = 0x02;
	out[3] = (uint8_t)rlen;
	memcpy(out + 4, r, rlen);
	size_t off = 4 + rlen;
	out[off] = 0x02;
	out[off + 1] = (uint8_t)slen;
	memcpy(out + off + 2, s, slen);
	*out_len = off + 2 + slen;
}

int fido_get_assertion(const fido_get_assert_req_t *req,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len)
{
	if (!fido_se_available())
		return CTAP2_ERR_UNSUPPORTED_ALGORITHM;  /* design A5 */

	/* User presence confirm BEFORE signing (design A3: no silent pulls). */
	if (!confirm_handler)
		return CTAP2_ERR_OPERATION_DENIED;
	if (!confirm_handler(req->rp_name, false))
		return CTAP2_ERR_OPERATION_DENIED;

	if (req->allowlist_credid_len == 0)
		return CTAP2_ERR_NO_CREDENTIALS;

	/* authData: flags UP, signCount (SE-internal counter, §4.3) */
	uint32_t sc = 0;
	if (se()->fido_signcount_read(&sc) != SE_OK)
		return CTAP2_ERR_PROCESSING;
	uint8_t flags = req->up_required ? FIDO_AT_FLAG_UP : 0;
	uint8_t authdata[FIDO_AT_HEADER_LEN];
	memcpy(authdata, req->rp_id_hash, 32);
	authdata[32] = flags;
	authdata[33] = (uint8_t)(sc >> 24);
	authdata[34] = (uint8_t)(sc >> 16);
	authdata[35] = (uint8_t)(sc >> 8);
	authdata[36] = (uint8_t)sc;

	/* signature over SHA-256(authData || clientDataHash) — ES256 is
	 * ECDSA-over-SHA-256, so the SE signs the 32-byte hash, not the raw
	 * concatenation (WebAuthn verifies the hash in the same step). */
	uint8_t prehash[FIDO_AT_HEADER_LEN + 32];
	memcpy(prehash, authdata, sizeof authdata);
	memcpy(prehash + sizeof authdata, req->client_data_hash, 32);
	uint8_t digest[32];
	os_sha256(prehash, sizeof prehash, digest);
	os_secure_bzero(prehash, sizeof prehash);
	uint8_t sig64[64];
	int rc = se()->fido_cred_sign(req->allowlist_credid,
	                              req->rp_id_hash, digest, sig64);
	os_secure_bzero(digest, sizeof digest);
	if (rc == SE_ERR_AUTH)
		return CTAP2_ERR_INVALID_CREDENTIAL;  /* tag/epoch mismatch */
	if (rc != SE_OK)
		return CTAP2_ERR_PROCESSING;

	/* WebAuthn §6.5.5: ES256 assertion signature MUST be DER-encoded. */
	uint8_t sig_der[72];
	size_t sig_der_len = 0;
	der_encode_ecdsa(sig64, sig_der, &sig_der_len);
	os_secure_bzero(sig64, sizeof sig64);

	/* response: {1:credential{"id":...,"type":...}, 2:authData, 3:signature}.
	 * The nested credential map MUST use text keys "id"/"type" per CTAP2
	 * spec; Chrome's CreateFromCBORValue only looks those up (integers
	 * caused kCtap2ErrInvalidCBOR). */
	cbor_writer_t w;
	cbor_writer_init(&w, resp, resp_cap);
	if (cbor_write_map_head(&w, 3) ||
	    cbor_write_uint(&w, 1) || cbor_write_map_head(&w, 2) ||
	    cbor_write_text(&w, "id") ||
	    cbor_write_bytes(&w, req->allowlist_credid, req->allowlist_credid_len) ||
	    cbor_write_text(&w, "type") || cbor_write_text(&w, "public-key") ||
	    cbor_write_uint(&w, 2) || cbor_write_bytes(&w, authdata, sizeof authdata) ||
	    cbor_write_uint(&w, 3) || cbor_write_bytes(&w, sig_der, sig_der_len))
		return CTAP1_ERR_OTHER;
	*resp_len = w.len;
	return CTAP2_OK;
}