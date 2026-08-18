/*
 * HardID Hardware Wallet — U2F (CTAP1) compatibility shim
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * See fido_u2f.h for the wire format. Credentials are the same SE-derived
 * key pairs CTAP2 uses; the U2F key handle IS the CTAP2 credID, so a
 * credential created over U2F later works over CTAP2 and vice versa.
 *
 * The attestation key/cert below is a DEV self-signed pair (documented as
 * such). Production devices get a provisioned attestation certificate from
 * the genuine-check flow; U2F RPs never verify the chain for registration
 * to succeed (Chrome accepts any attestation for U2F 2FA keys).
 */

#include "fido_u2f.h"
#include "fido_core.h"
#include "se_driver.h"
#include "secp256r1.h"
#include "hkdf.h"
#include "sha256.h"
#include "secure_zero.h"
#include <string.h>

/* DEV attestation private key (P-256). Matches the certificate below. */
static const uint8_t ATT_PRIV[32] = {
	0x05,0x11,0x69,0xc3,0x06,0x58,0xce,0xd6,0x9d,0xb4,0x50,0xd6,0x7f,0x02,0xee,0x14,
	0x73,0xe8,0xb7,0xc1,0xd7,0xbc,0x84,0x1e,0x31,0x98,0x60,0x94,0x3f,0xa4,0x6d,0x27
};

/* DEV self-signed attestation certificate (DER, 366 bytes). */
static const uint8_t ATT_CERT[] = {
	0x30,0x82,0x01,0x6a,0x30,0x82,0x01,0x11,0xa0,0x03,0x02,0x01,0x02,0x02,0x01,0x01,
	0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,0xce,0x3d,0x04,0x03,0x02,0x30,0x3f,0x31,0x25,
	0x30,0x23,0x06,0x03,0x55,0x04,0x03,0x0c,0x1c,0x48,0x61,0x72,0x64,0x49,0x44,0x20,
	0x55,0x32,0x46,0x20,0x41,0x74,0x74,0x65,0x73,0x74,0x61,0x74,0x69,0x6f,0x6e,0x20,
	0x28,0x44,0x45,0x56,0x29,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x0a,0x0c,0x0d,
	0x4c,0x69,0x67,0x68,0x74,0x6e,0x69,0x6e,0x67,0x41,0x53,0x49,0x43,0x30,0x1e,0x17,
	0x0d,0x32,0x36,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x17,0x0d,
	0x33,0x36,0x30,0x31,0x30,0x31,0x30,0x30,0x30,0x30,0x30,0x30,0x5a,0x30,0x3f,0x31,
	0x25,0x30,0x23,0x06,0x03,0x55,0x04,0x03,0x0c,0x1c,0x48,0x61,0x72,0x64,0x49,0x44,
	0x20,0x55,0x32,0x46,0x20,0x41,0x74,0x74,0x65,0x73,0x74,0x61,0x74,0x69,0x6f,0x6e,
	0x20,0x28,0x44,0x45,0x56,0x29,0x31,0x16,0x30,0x14,0x06,0x03,0x55,0x04,0x0a,0x0c,
	0x0d,0x4c,0x69,0x67,0x68,0x74,0x6e,0x69,0x6e,0x67,0x41,0x53,0x49,0x43,0x30,0x59,
	0x30,0x13,0x06,0x07,0x2a,0x86,0x48,0xce,0x3d,0x02,0x01,0x06,0x08,0x2a,0x86,0x48,
	0xce,0x3d,0x03,0x01,0x07,0x03,0x42,0x00,0x04,0xed,0x13,0x75,0x8d,0xcc,0xee,0xf8,
	0xb4,0xdd,0xf5,0xdd,0x8a,0x79,0xde,0x23,0xea,0x1c,0x68,0x54,0x13,0x6a,0xd1,0x9f,
	0x72,0xb8,0xaa,0xf1,0xcc,0xb2,0x22,0x67,0x80,0x98,0xc9,0x12,0xf6,0xfe,0xe5,0x86,
	0x0e,0x50,0xc1,0xa6,0x7f,0xc1,0x18,0x8b,0xad,0x33,0x1b,0x45,0x79,0xe6,0xfb,0x79,
	0x61,0x1d,0x5c,0x12,0x65,0x22,0xa8,0x2e,0xab,0x30,0x0a,0x06,0x08,0x2a,0x86,0x48,
	0xce,0x3d,0x04,0x03,0x02,0x03,0x47,0x00,0x30,0x44,0x02,0x20,0x45,0x59,0xa1,0xe9,
	0x74,0xee,0xb1,0xf5,0x1e,0xe1,0xb6,0x11,0xcb,0x30,0x1b,0x12,0x77,0x13,0x4a,0x10,
	0x25,0x76,0xbc,0xab,0x3c,0xb5,0xfe,0xda,0x1a,0x05,0x35,0x71,0x02,0x20,0x0d,0x34,
	0xf8,0xe5,0xbc,0xeb,0x0a,0x7f,0x52,0x13,0x41,0xdc,0xc9,0xa1,0xe9,0xa8,0xe6,0x93,
	0xab,0xb4,0xb8,0x3d,0x18,0xbc,0x2f,0xa7,0x2b,0xa6,0x8b,0x63,0xba,0x57
};
#define ATT_CERT_LEN ((uint16_t)sizeof(ATT_CERT))

#define U2F_SW_OK            0x9000
#define U2F_SW_WRONG_DATA    0x6A80
#define U2F_SW_CONDITIONS    0x6985

extern fido_confirm_fn fido_confirm_get(void);

static size_t put_sw(uint8_t *out, uint16_t sw)
{
	out[0] = (uint8_t)(sw >> 8);
	out[1] = (uint8_t)sw;
	return 2;
}

static const se_driver_t *u2f_se(void)
{
	const se_driver_t *se = se_active();
	if (!se || !se->fido_cred_make || !se->fido_cred_sign ||
	    !se->fido_signcount_read || !se->fido_cred_exists)
		return NULL;
	return se;
}

/* U2F_REGISTER: create a credential bound to appid, return
 * 05 || pub(65) || khLen(21) || credid || cert || attSig(64) || 9000. */
static size_t u2f_register(const uint8_t *challenge, const uint8_t *appid,
                           uint8_t *out, size_t cap)
{
	const se_driver_t *se = u2f_se();
	if (!se)
		return put_sw(out, U2F_SW_WRONG_DATA);

	/* U2F requires a user-presence gesture for registration. */
	if (!fido_confirm_get() || !fido_confirm_get()("U2F Register", true))
		return put_sw(out, U2F_SW_CONDITIONS);

	uint8_t pub[65], credid[FIDO_CREDID_LEN];
	if (se->fido_cred_make(appid, pub, credid) != SE_OK)
		return put_sw(out, U2F_SW_WRONG_DATA);

	/* attestation signature over 00 || appid || challenge || kh || pubkey */
	uint8_t pre[1 + 32 + 32 + FIDO_CREDID_LEN + 65];
	pre[0] = 0;
	memcpy(pre + 1, appid, 32);
	memcpy(pre + 33, challenge, 32);
	memcpy(pre + 65, credid, FIDO_CREDID_LEN);
	memcpy(pre + 65 + FIDO_CREDID_LEN, pub, 65);
	uint8_t digest[32], sig[64], sig_der[72];
	size_t sig_der_len = 0;
	os_sha256(pre, sizeof pre, digest);
	os_secure_bzero(pre, sizeof pre);
	if (os_secp256r1_sign(ATT_PRIV, digest, sig) != 0) {
		os_secure_bzero(digest, sizeof digest);
		return put_sw(out, U2F_SW_WRONG_DATA);
	}
	os_secure_bzero(digest, sizeof digest);
	/* U2F signatures are X9.62 (DER Ecdsa-Sig-Value), NOT raw r||s —
	 * Chrome parses them with ECDSA_SIG_from_bytes (BoringSSL, DER only)
	 * and rejects raw 64-byte signatures. */
	fido_der_encode_ecdsa(sig, sig_der, &sig_der_len);
	os_secure_bzero(sig, sizeof sig);

	size_t need = 1 + 65 + 1 + FIDO_CREDID_LEN + ATT_CERT_LEN + sig_der_len + 2;
	if (cap < need)
		return put_sw(out, U2F_SW_WRONG_DATA);

	size_t n = 0;
	out[n++] = 0x05;
	memcpy(out + n, pub, 65); n += 65;
	out[n++] = FIDO_CREDID_LEN;
	memcpy(out + n, credid, FIDO_CREDID_LEN); n += FIDO_CREDID_LEN;
	memcpy(out + n, ATT_CERT, ATT_CERT_LEN); n += ATT_CERT_LEN;
	memcpy(out + n, sig_der, sig_der_len); n += sig_der_len;
	out[n++] = 0x90; out[n++] = 0x00;
	return n;
}

/* U2F_AUTHENTICATE. check-only (P1=0x07): 6985 when the key handle is ours,
 * 6A80 otherwise. enforce (P1=0x03): confirm then sign. */
static size_t u2f_authenticate(uint8_t p1, const uint8_t *challenge,
                               const uint8_t *appid,
                               const uint8_t *kh, size_t kh_len,
                               uint8_t *out, size_t cap)
{
	const se_driver_t *se = u2f_se();
	if (!se || kh_len != FIDO_CREDID_LEN)
		return put_sw(out, U2F_SW_WRONG_DATA);
	if (se->fido_cred_exists(kh, appid) != SE_OK)
		return put_sw(out, U2F_SW_WRONG_DATA);

	if (p1 == 0x07)   /* check-only: credential is present */
		return put_sw(out, U2F_SW_CONDITIONS);
	if (p1 != 0x03)   /* only enforce + check-only are meaningful here */
		return put_sw(out, U2F_SW_WRONG_DATA);

	/* enforce: user presence, then sign appid || UP || counter || challenge */
	if (!fido_confirm_get() || !fido_confirm_get()("U2F Login", false))
		return put_sw(out, U2F_SW_CONDITIONS);

	uint32_t counter = 0;
	if (se->fido_signcount_read(&counter) != SE_OK)
		return put_sw(out, U2F_SW_WRONG_DATA);

	uint8_t pre[32 + 1 + 4 + 32];
	memcpy(pre, appid, 32);
	pre[32] = 0x01;   /* UP */
	pre[33] = (uint8_t)(counter >> 24);
	pre[34] = (uint8_t)(counter >> 16);
	pre[35] = (uint8_t)(counter >> 8);
	pre[36] = (uint8_t)counter;
	memcpy(pre + 37, challenge, 32);
	uint8_t digest[32], sig[64];
	os_sha256(pre, sizeof pre, digest);
	os_secure_bzero(pre, sizeof pre);
	int rc = se->fido_cred_sign(kh, appid, digest, sig);
	os_secure_bzero(digest, sizeof digest);
	if (rc != SE_OK) {
		os_secure_bzero(sig, sizeof sig);
		return put_sw(out, U2F_SW_WRONG_DATA);
	}

	/* X9.62 DER signature (see u2f_register note). */
	uint8_t sig_der[72];
	size_t sig_der_len = 0;
	fido_der_encode_ecdsa(sig, sig_der, &sig_der_len);
	os_secure_bzero(sig, sizeof sig);

	if (cap < 1 + 4 + sig_der_len + 2)
		return put_sw(out, U2F_SW_WRONG_DATA);
	size_t n = 0;
	out[n++] = 0x01;
	out[n++] = (uint8_t)(counter >> 24);
	out[n++] = (uint8_t)(counter >> 16);
	out[n++] = (uint8_t)(counter >> 8);
	out[n++] = (uint8_t)counter;
	memcpy(out + n, sig_der, sig_der_len); n += sig_der_len;
	out[n++] = 0x90; out[n++] = 0x00;
	return n;
}

void fido_u2f_handle(const uint8_t *apdu, size_t apdu_len,
                     uint8_t *out, size_t out_cap, size_t *out_len)
{
	static const uint8_t VERSION_RESP[] = {'U','2','F','_','V','2',0x90,0x00};

	*out_len = 0;
	if (apdu_len < 4 || out_cap < 8)
		return;

	uint8_t ins = apdu[1];
	if (ins == 0x03) {   /* U2F_VERSION */
		memcpy(out, VERSION_RESP, sizeof VERSION_RESP);
		*out_len = sizeof VERSION_RESP;
		return;
	}
	/* extended length: apdu[4]==0, Lc at [5..6] */
	if (apdu_len < 7 || apdu[4] != 0) {
		*out_len = put_sw(out, U2F_SW_WRONG_DATA);
		return;
	}
	size_t lc = ((size_t)apdu[5] << 8) | apdu[6];
	if (apdu_len < 7 + lc) {
		*out_len = put_sw(out, U2F_SW_WRONG_DATA);
		return;
	}
	const uint8_t *data = apdu + 7;

	if (ins == 0x01) {   /* U2F_REGISTER */
		if (lc != 64) {
			*out_len = put_sw(out, U2F_SW_WRONG_DATA);
			return;
		}
		*out_len = u2f_register(data, data + 32, out, out_cap);
		return;
	}
	if (ins == 0x02) {   /* U2F_AUTHENTICATE */
		if (lc < 65) {
			*out_len = put_sw(out, U2F_SW_WRONG_DATA);
			return;
		}
		size_t kh_len = data[64];
		if (lc != 65 + kh_len) {
			*out_len = put_sw(out, U2F_SW_WRONG_DATA);
			return;
		}
		*out_len = u2f_authenticate(apdu[2], data, data + 32,
		                            data + 65, kh_len, out, out_cap);
		return;
	}
	*out_len = put_sw(out, U2F_SW_WRONG_DATA);
}
