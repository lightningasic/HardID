/*
 * HardID Hardware Wallet — FIDO core (credential lifecycle)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Credential lifecycle: makeCredential / getAssertion / GetInfo. All
 * secret-key work is delegated to the SE (se_driver.h fido_cred_*);
 * this module only assembles public authenticatorData and attestation
 * objects. Callers (core/ctap2.c) parse the CTAP2 CBOR request into the
 * *_req_t structs below and encode the returned response buffer.
 */

#ifndef HARDID_FIDO_CORE_H
#define HARDID_FIDO_CORE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "fido.h"
#include "se_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- parsed makeCredential request ---- */
#define FIDO_MAX_EXCLUDE 4   /* max excludeCredentials parsed per request */

typedef struct fido_make_cred_req {
	uint8_t  client_data_hash[32];
	uint8_t  rp_id_hash[32];
	const char *rp_name;      /* display only, may be NULL */
	const char *user_name;    /* display only, may be NULL */
	bool     up_required;     /* options.up (default true) */
	uint8_t  exclude_credid[FIDO_MAX_EXCLUDE][FIDO_CREDID_LEN];
	size_t   exclude_count;   /* number of excludeCredentials parsed */
} fido_make_cred_req_t;

/* ---- parsed getAssertion request ---- */
typedef struct fido_get_assert_req {
	uint8_t  client_data_hash[32];
	uint8_t  rp_id_hash[32];
	const char *rp_name;      /* display only, may be NULL */
	bool     up_required;     /* options.up (default true) */
	/* allowList[0] is the credential the host asks us to sign with. The
	 * first version supports exactly one allowList entry (per design
	 * GetInfo maxCredentialCountInList=8 the host may send more, but we
	 * evaluate only the first and rely on per-RP tag binding). */
	uint8_t  allowlist_credid[FIDO_CREDID_LEN];
	size_t   allowlist_credid_len;
} fido_get_assert_req_t;

/* User-presence confirmation hook. Called with the RP display name and
 * whether this is a registration (true) or login (false). Must return 1
 * to approve, 0 to deny. Default NULL => every operation is denied
 * (never signs without confirmation, design A3). Wired by the UI layer
 * (esp-idf-s3/fido_esp.c) to the touch confirm screen. */
typedef int (*fido_confirm_fn)(const char *rp_name, bool is_register);
void fido_set_confirm_handler(fido_confirm_fn fn);

/* GetInfo response (CBOR). Static per design doc §3.2. */
int fido_getinfo(uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Execute makeCredential; returns CTAP2 status code, writes CBOR response
 * (without the leading status byte — ctap2.c prepends it) on success. */
int fido_make_credential(const fido_make_cred_req_t *req,
                         uint8_t *resp, size_t resp_cap, size_t *resp_len);

/* Execute getAssertion; CTAP2 status code + CBOR response on success. */
int fido_get_assertion(const fido_get_assert_req_t *req,
                       uint8_t *resp, size_t resp_cap, size_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_FIDO_CORE_H */