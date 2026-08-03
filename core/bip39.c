/*
 * OpenShield Hardware Wallet — BIP39 mnemonic
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "bip39.h"
#include "bip39_wordlist.h"
#include "sha512.h"
#include "sha256.h"
#include <string.h>

int os_bip39_word_index(const char *word)
{
	for (int i = 0; i < 2048; i++)
		if (strcmp(os_bip39_wordlist[i], word) == 0)
			return i;
	return -1;
}

int os_bip39_entropy_to_mnemonic(const uint8_t *entropy, size_t elen,
                                 char *mnemonic, size_t mmax)
{
	/* ENT must be 128..256 bits in 32-bit steps */
	if (elen < 16 || elen > 32 || elen % 4 != 0)
		return 0;
	size_t cs_bits = elen / 4;              /* checksum length in bits */
	size_t total_bits = elen * 8 + cs_bits; /* 132..264 */
	int words = (int)(total_bits / 11);

	uint8_t hash[32];
	os_sha256(entropy, elen, hash);

	/* bit stream reader over entropy || checksum */
	size_t need = (size_t)words * 11;      /* bits */
	uint8_t stream[33];                     /* max 32 entropy + 1 checksum byte */
	memcpy(stream, entropy, elen);
	stream[elen] = hash[0];                 /* only first cs_bits used */

	size_t off = 0;
	size_t out = 0;
	for (int w = 0; w < words; w++) {
		uint16_t idx = 0;
		for (int b = 0; b < 11; b++) {
			size_t bit = off + b;
			uint8_t bitval = (stream[bit / 8] >> (7 - (bit % 8))) & 1;
			idx = (idx << 1) | bitval;
		}
		off += 11;
		const char *word = os_bip39_wordlist[idx];
		size_t wl = strlen(word);
		if (out + wl + 1 >= mmax)
			return 0;
		if (w) mnemonic[out++] = ' ';
		memcpy(mnemonic + out, word, wl);
		out += wl;
	}
	mnemonic[out] = 0;
	(void)need;
	return words;
}

size_t os_bip39_mnemonic_to_entropy(const char *mnemonic,
                                    uint8_t *entropy, size_t emax)
{
	/* split into words, collect 11-bit indices */
	uint16_t idx[24];
	int words = 0;
	const char *p = mnemonic;
	while (*p && words < 24) {
		while (*p == ' ') p++;
		if (!*p) break;
		const char *start = p;
		while (*p && *p != ' ') p++;
		size_t wl = (size_t)(p - start);
		char word[16];
		if (wl >= sizeof word) return 0;
		memcpy(word, start, wl);
		word[wl] = 0;
		int wi = os_bip39_word_index(word);
		if (wi < 0) return 0;
		idx[words++] = (uint16_t)wi;
	}
	/* reject trailing garbage: after collecting words there must be only
	 * spaces left, never a 25th word silently ignored */
	while (*p == ' ') p++;
	if (*p != 0)
		return 0;
	if (words != 12 && words != 15 && words != 18 && words != 21 && words != 24)
		return 0;

	size_t total_bits = (size_t)words * 11;
	size_t cs_bits = total_bits / 33;
	size_t ent_bits = total_bits - cs_bits;
	size_t ent_len = ent_bits / 8;
	if (ent_len > emax)
		return 0;

	/* pack 11-bit indices into bytes */
	uint8_t stream[33];
	memset(stream, 0, sizeof stream);
	for (int w = 0; w < words; w++) {
		for (int b = 0; b < 11; b++) {
			size_t bit = (size_t)w * 11 + b;
			uint8_t bitval = (idx[w] >> (10 - b)) & 1;
			if (bitval)
				stream[bit / 8] |= (uint8_t)(1 << (7 - (bit % 8)));
		}
	}
	memcpy(entropy, stream, ent_len);

	/* verify checksum */
	uint8_t hash[32];
	os_sha256(entropy, ent_len, hash);
	uint8_t cs_stream = stream[ent_len];
	uint8_t cs_hash = hash[0];
	uint8_t mask = (uint8_t)(0xFF << (8 - cs_bits));
	if ((cs_stream & mask) != (cs_hash & mask))
		return 0;
	return ent_len;
}

void os_bip39_mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                               uint8_t *seed64)
{
	char salt[128];
	size_t sl = 0;
	const char *prefix = "mnemonic";
	memcpy(salt, prefix, 8);
	sl = 8;
	if (passphrase) {
		size_t pl = strlen(passphrase);
		if (sl + pl > sizeof salt) pl = sizeof salt - sl;
		memcpy(salt + sl, passphrase, pl);
		sl += pl;
	}
	os_pbkdf2_sha512((const uint8_t *)mnemonic, strlen(mnemonic),
	                 (const uint8_t *)salt, sl, 2048, seed64, 64);
}
