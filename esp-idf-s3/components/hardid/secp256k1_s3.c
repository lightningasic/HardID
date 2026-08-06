/*
 * HardID — secp256k1 backend for ESP32-S3 (Xtensa)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * ESP32-P4 (RISC-V) supports `unsigned __int128`, but the ESP32-S3 Xtensa
 * compiler does not, so core/secp256k1.c cannot build for this target.
 * This file provides the same secp256k1.h interface on top of mbedTLS (which
 * ESP-IDF links anyway). Interface contract (secp256k1.h) is unchanged.
 *
 * SECURITY NOTE: Non-constant-time, as in the original. This is fine for
 * xpub derivation and host-side testing; device signing must go through the
 * Secure Element's own constant-time secp256k1. See bip32.h.
 */

#include "secp256k1.h"
#include <string.h>

#include "esp_random.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"

#define SECP256K1_GROUP_ID MBEDTLS_ECP_DP_SECP256K1

/* mbedTLS scalar-mult blinds the operation using the RNG. esp_random fills
 * 4 bytes per call; mbedtls wants a caller-agnostic (ctx, buf, len) signature,
 * so adapt it here. */
static int rng_esp(void *ctx, unsigned char *buf, size_t len)
{
	(void)ctx;
	while (len > 0) {
		size_t chunk = len > 4 ? 4 : len;
		uint32_t w = esp_random();
		memcpy(buf, &w, chunk);
		buf += chunk;
		len -= chunk;
	}
	return 0;
}

/* Opaque parsed point (OS_SECP256K1_POINT_SIZE bytes): we store an
 * mbedtls_ecp_point. The caller only treats it as an opaque buffer. */
static mbedtls_ecp_point *pt_from_buf(void *point_buf)
{
	return (mbedtls_ecp_point *)point_buf;
}

static int load_grp(mbedtls_ecp_group *grp)
{
	mbedtls_ecp_group_init(grp);
	return mbedtls_ecp_group_load(grp, SECP256K1_GROUP_ID);
}

int os_secp256k1_pubkey(const uint8_t *priv32, uint8_t *pub33)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi k;
	mbedtls_ecp_point R;
	size_t olen = 33;
	int rc;

	if (load_grp(&grp) != 0)
		return -1;
	mbedtls_mpi_init(&k);
	mbedtls_ecp_point_init(&R);

	if (mbedtls_mpi_read_binary(&k, priv32, 32) != 0 ||
	    mbedtls_ecp_check_privkey(&grp, &k) != 0) {
		rc = -1;               /* 0 or >= n -> invalid */
		goto out;
	}
	if (mbedtls_ecp_mul(&grp, &R, &k, &grp.G, rng_esp, NULL) != 0) {
		rc = -1;
		goto out;
	}
	if (mbedtls_ecp_point_write_binary(&grp, &R, MBEDTLS_ECP_PF_COMPRESSED,
	                                   &olen, pub33, 33) != 0 ||
	    olen != 33) {
		rc = -1;
		goto out;
	}
	rc = 0;
out:
	mbedtls_ecp_point_free(&R);
	mbedtls_mpi_free(&k);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

void os_secp256k1_scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi A, B, X;

	/* mod n for the scalar arithmetic */
	load_grp(&grp);
	mbedtls_mpi_init(&A); mbedtls_mpi_init(&B); mbedtls_mpi_init(&X);
	mbedtls_mpi_read_binary(&A, a, 32);
	mbedtls_mpi_read_binary(&B, b, 32);
	if (mbedtls_mpi_mul_mpi(&X, &A, &B) == 0)
		mbedtls_mpi_mod_mpi(&X, &X, &grp.N);
	mbedtls_mpi_write_binary(&X, r, 32);
	mbedtls_mpi_free(&X); mbedtls_mpi_free(&B); mbedtls_mpi_free(&A);
	mbedtls_ecp_group_free(&grp);
}

void os_secp256k1_scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi A, B, X;
	load_grp(&grp);
	mbedtls_mpi_init(&A); mbedtls_mpi_init(&B); mbedtls_mpi_init(&X);
	mbedtls_mpi_read_binary(&A, a, 32);
	mbedtls_mpi_read_binary(&B, b, 32);
	if (mbedtls_mpi_add_mpi(&X, &A, &B) == 0)
		mbedtls_mpi_mod_mpi(&X, &X, &grp.N);
	mbedtls_mpi_write_binary(&X, r, 32);
	mbedtls_mpi_free(&X); mbedtls_mpi_free(&B); mbedtls_mpi_free(&A);
	mbedtls_ecp_group_free(&grp);
}

int os_secp256k1_scalar_inv(uint8_t *r, const uint8_t *a)
{
	mbedtls_ecp_group grp;
	mbedtls_mpi A, X;
	int rc = 0;
	load_grp(&grp);
	mbedtls_mpi_init(&A); mbedtls_mpi_init(&X);
	mbedtls_mpi_read_binary(&A, a, 32);
	if (mbedtls_mpi_cmp_int(&A, 0) == 0) {
		rc = -1;
	} else if (mbedtls_mpi_inv_mod(&X, &A, &grp.N) == 0) {
		mbedtls_mpi_write_binary(&X, r, 32);
	} else {
		rc = -1;
	}
	mbedtls_mpi_free(&X); mbedtls_mpi_free(&A);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int os_secp256k1_parse_pubkey(const uint8_t *pub33, void *point_out)
{
	mbedtls_ecp_group grp;
	mbedtls_ecp_point *P = pt_from_buf(point_out);
	int rc;

	if (load_grp(&grp) != 0)
		return -1;
	mbedtls_ecp_point_init(P);
	rc = mbedtls_ecp_point_read_binary(&grp, P, pub33, 33);
	mbedtls_ecp_group_free(&grp);
	return rc == 0 ? 0 : -1;
}

int os_secp256k1_point_mul(const void *point, const uint8_t *k32, uint8_t *pub33)
{
	mbedtls_ecp_group grp;
	const mbedtls_ecp_point *P = (const mbedtls_ecp_point *)point;
	mbedtls_mpi k;
	mbedtls_ecp_point R;
	size_t olen = 0;
	int rc = -1;

	if (load_grp(&grp) != 0)
		return -1;
	mbedtls_mpi_init(&k);
	mbedtls_ecp_point_init(&R);
	if (mbedtls_mpi_read_binary(&k, k32, 32) == 0 &&
	    mbedtls_ecp_mul(&grp, &R, &k, P, rng_esp, NULL) == 0 &&
	    mbedtls_ecp_point_write_binary(&grp, &R, MBEDTLS_ECP_PF_COMPRESSED,
	                                   &olen, pub33, 33) == 0 &&
	    olen == 33)
		rc = 0;
	mbedtls_ecp_point_free(&R);
	mbedtls_mpi_free(&k);
	mbedtls_ecp_group_free(&grp);
	return rc;
}

int os_secp256k1_point_add(const void *a, const void *b, uint8_t *pub33)
{
	/* R = 1*a + 1*b  == a + b  (via mbedtls_ecp_muladd) */
	mbedtls_ecp_group grp;
	const mbedtls_ecp_point *A = (const mbedtls_ecp_point *)a;
	const mbedtls_ecp_point *B = (const mbedtls_ecp_point *)b;
	mbedtls_mpi one;
	mbedtls_ecp_point R;
	size_t olen = 33;
	int rc = -1;

	if (load_grp(&grp) != 0)
		return -1;
	mbedtls_mpi_init(&one);
	mbedtls_ecp_point_init(&R);
	mbedtls_mpi_lset(&one, 1);
	if (mbedtls_ecp_muladd(&grp, &R, &one, A, &one, B) == 0 &&
	    mbedtls_ecp_point_write_binary(&grp, &R, MBEDTLS_ECP_PF_COMPRESSED,
	                                   &olen, pub33, 33) == 0 &&
	    olen == 33)
		rc = 0;
	mbedtls_ecp_point_free(&R);
	mbedtls_mpi_free(&one);
	mbedtls_ecp_group_free(&grp);
	return rc;
}