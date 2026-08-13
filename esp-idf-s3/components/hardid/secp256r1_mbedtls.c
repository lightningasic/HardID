/*
 * HardID Hardware Wallet — secp256r1 (P-256) device backend via mbedtls
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * ESP-IDF device build of the secp256r1 API (core/secp256r1.h). The
 * clean-room core/secp256r1.c uses __int128, which the xtensa-esp32s3
 * toolchain does not support, so the ESP32-S3 firmware provides the same
 * `os_secp256r1_*` symbols backed by the bundled mbedtls software ECC
 * (decision: device uses mbedtls; host tests keep the pure impl, so the
 * two agree — both are standard P-256 + RFC 6979 deterministic nonce).
 *
 * Only the two entry points the SE mock actually calls are implemented.
 * Output formats match core/secp256r1.h exactly:
 *   - os_secp256r1_pubkey(): 65-byte UNCOMPRESSED public key (0x04||X||Y),
 *     required by WebAuthn COSE keys.
 *   - os_secp256r1_sign(): 64-byte compact (r||s), big-endian, LOW-s
 *     (mbedtls enforces low-s), deterministic (RFC 6979) via
 *     mbedtls_ecdsa_sign_det_ext() with MBEDTLS_MD_SHA256 (the caller has
 *     already hashed to a 32-byte digest; md_alg only picks the RFC 6979
 *     HMAC hash, which must be SHA-256 to match the host pure impl).
 *
 * Links against mbedtls (idf_component_register REQUIRES mbedtls).
 */

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/hmac_drbg.h"
#include "secp256r1.h"

/* CSPRNG used only for ECDSA blinding (not for key/nonce derivation — the
 * nonce is deterministic RFC 6979). ESP-IDF provides the RNG. */
static int hardid_esp_rng(void *ctx, unsigned char *out, size_t len)
{
	(void)ctx;
	extern uint32_t esp_random(void);
	while (len >= 4) {
		uint32_t x = esp_random();
		memcpy(out, &x, 4);
		out += 4; len -= 4;
	}
	if (len) {
		uint32_t x = esp_random();
		memcpy(out, &x, len);
	}
	return 0;
}

int os_secp256r1_pubkey(const uint8_t *priv32, uint8_t *pub65)
{
	int rc = -1;
	mbedtls_ecp_group grp;
	mbedtls_mpi d;
	mbedtls_ecp_point Q;
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_ecp_point_init(&Q);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
		goto out;
	if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0)
		goto out;
	/* validate 0 < priv < n */
	if (mbedtls_ecp_check_privkey(&grp, &d) != 0)
		goto out;
	if (mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, hardid_esp_rng, NULL) != 0)
		goto out;
	/* serialize 0x04||X||Y (65 bytes), validates on-curve */
	size_t olen = 0;
	if (mbedtls_ecp_point_write_binary(&grp, &Q,
	                                  MBEDTLS_ECP_PF_UNCOMPRESSED,
	                                  &olen, pub65, 65) != 0 ||
	    olen != 65)
		goto out;
	rc = 0;

out:
	mbedtls_ecp_point_free(&Q);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int os_secp256r1_sign(const uint8_t priv32[32], const uint8_t hash32[32],
		      uint8_t sig64[64])
{
	int rc = -1;
	mbedtls_ecp_group grp;
	mbedtls_mpi d, r, s;
	mbedtls_ecp_group_init(&grp);
	mbedtls_mpi_init(&d);
	mbedtls_mpi_init(&r);
	mbedtls_mpi_init(&s);

	if (mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
		goto out;
	if (mbedtls_mpi_read_binary(&d, priv32, 32) != 0)
		goto out;
	if (mbedtls_ecp_check_privkey(&grp, &d) != 0)
		goto out;

	/* Deterministic RFC 6979 nonce. md_alg selects the HMAC_DRBG hash used
	 * for the RFC 6979 nonce — it must be SHA-256 to match the host pure
	 * impl (core/rfc6979.c uses os_hmac_sha256). The 32-byte message is NOT
	 * re-hashed (mbedtls signs buf directly); MD_NONE would make
	 * mbedtls_md_info_from_type() return NULL and the call fail with
	 * BAD_INPUT_DATA. Low-s enforced by mbedtls. */
	if (mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
	                               hash32, 32, MBEDTLS_MD_SHA256,
	                               hardid_esp_rng, NULL) != 0)
		goto out;

	/* serialize r||s, both 32-byte big-endian -> 64-byte compact */
	if (mbedtls_mpi_write_binary(&r, sig64, 32) != 0)
		goto out;
	if (mbedtls_mpi_write_binary(&s, sig64 + 32, 32) != 0)
		goto out;
	rc = 0;

out:
	mbedtls_mpi_free(&s);
	mbedtls_mpi_free(&r);
	mbedtls_mpi_free(&d);
	mbedtls_ecp_group_free(&grp);
	return rc;
}