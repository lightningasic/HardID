/*
 * HardID Hardware Wallet — BIP39 mnemonic
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * entropy -> mnemonic (with checksum), mnemonic -> entropy (validated),
 * mnemonic (+passphrase) -> 64-byte seed via PBKDF2-HMAC-SHA512.
 */

#ifndef HARDID_BIP39_H
#define HARDID_BIP39_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* mnemonic buffer sizing: 24 words * (8 chars + space) + NUL */
#define OS_BIP39_MNEMONIC_MAX 256
#define OS_BIP39_SEED_LEN 64

/* Encode entropy (16/20/24/28/32 bytes) into a space-separated mnemonic.
 * Returns number of words (12/15/18/21/24), or 0 on bad entropy length. */
int os_bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t elen,
                                 char *mnemonic, size_t mmax);

/* Validate checksum + decode a mnemonic back into entropy.
 * Returns entropy length in bytes, or 0 on invalid words/checksum. */
size_t os_bip39_mnemonic_to_entropy(const char *mnemonic,
                                    uint8_t *entropy, size_t emax);

/* Derive the 64-byte seed from mnemonic + optional passphrase. */
void os_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                               uint8_t *seed64);

/* Look up a word in the standard list; returns index or -1. */
int os_bip39_word_index(const char *word);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_BIP39_H */
