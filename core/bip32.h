/*
 * HardID Hardware Wallet — BIP32 HD key derivation
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * secp256k1 private/public derivation + xpub/xprv serialization.
 * Includes a self-contained secp256k1 field/point implementation
 * (sufficient for pubkey-from-privkey; NOT constant-time — see note).
 *
 * SECURITY NOTE: This scalar-mult is for deriving xpubs and for the
 * emulator/host. On-device signing must use the SE's hardware secp256k1
 * (constant-time, side-channel hardened). Do NOT sign with this on MCU.
 */

#ifndef HARDID_BIP32_H
#define HARDID_BIP32_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OS_BIP32_XKEY_MAX 112

typedef struct {
	uint8_t  priv[32];        /* private key (zeroed in pubonly nodes) */
	uint8_t  pub[33];         /* compressed public key */
	uint8_t  chain_code[32];
	uint8_t  depth;
	uint32_t fingerprint;     /* parent fingerprint */
	uint32_t child_num;
	bool     has_priv;
} os_hdnode;

/* Derive master node from a 64-byte BIP39 seed. Returns 0 on success. */
int os_bip32_from_seed(const uint8_t *seed, size_t seed_len, os_hdnode *node);

/* secp256k1 public key (compressed, 33 bytes) from 32-byte private key.
 * Returns 0 on success, -1 if privkey invalid (0 or >= n). */
int os_secp256k1_pubkey(const uint8_t *priv32, uint8_t *pub33);

/* Child key derivation. index >= 0x80000000 = hardened (needs priv). */
int os_bip32_ckd(const os_hdnode *parent, uint32_t index, os_hdnode *child);

/* Derive along a path like m/44'/0'/0'/0/0. Returns 0 on success. */
int os_bip32_derive_path(os_hdnode *node, const char *path);

/* 4-byte fingerprint of a node (first 4 of HASH160(pub)). */
uint32_t os_bip32_fingerprint(const os_hdnode *node);

/* Serialize as base58check xprv/xpub. Returns length or 0. */
size_t os_bip32_serialize(const os_hdnode *node, bool private,
                          uint32_t version, char *out, size_t outmax);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_BIP32_H */
