/*
 * HardID Hardware Wallet — BIP39 mnemonic
 * Copyright (C) 2026 LightningASIC / HardID contributors
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

/* Resolve a partial word the user has typed against the wordlist.
 *
 * The BIP39 English list is free of 4-char-prefix collisions: every word is
 * uniquely identified by its first 4 letters (or by the whole word when the
 * word is shorter than 4 letters). So to enter a seed word on a tiny keyboard
 * the user only needs to type its unique prefix.
 *
 * Rules applied here:
 *   - 4 letters typed matches every word with that 4-letter prefix.
 *   - fewer than 4 letters matches only words whose full length equals the
 *     typed length (i.e. short words like "add"), never a longer word that
 *     merely begins with those letters.
 * Returns the unique word index (0..2047), or -1 if none or ambiguous. */
int os_bip39_word_resolve_prefix(const char *prefix, size_t n)
{
	int match = -1;
	if (n < 1 || n > 4)
		return -1;
	for (int i = 0; i < 2048; i++) {
		const char *w = os_bip39_wordlist[i];
		size_t wl = strlen(w);
		if (wl < n)
			continue;                 /* typed more than the word has */
		if (strncmp(w, prefix, n) != 0)
			continue;                 /* prefix mismatch */
		if (n != 4 && wl != n)
			continue;                 /* short prefix: word must be exactly n */
		if (match >= 0)
			return -1;                /* ambiguous: two words share prefix */
		match = i;
	}
	return match;
}

/* Try to auto-commit a typed prefix to a single word.
 *  - 4-char prefix: the BIP39 list is constructed so every word is uniquely
 *    identified by its first 4 letters, so the (usually only) word starting
 *    with the prefix is committed.
 *  - shorter prefix (1..3 chars): commit only when the prefix equals a real
 *    word AND no longer word starts with it — e.g. "add" is left open so the
 *    user can continue to "addict"; "zoo" (no "zoo*") commits immediately. */
int os_bip39_word_try_commit(const char *prefix, size_t n)
{
	int exact = -1;
	if (n < 1 || n > 4)
		return -1;
	if (n == 4) {
		int match = -1;
		for (int i = 0; i < 2048; i++) {
			if (strncmp(os_bip39_wordlist[i], prefix, 4) == 0) {
				if (match >= 0) return -1; /* not unique */
				match = i;
			}
		}
		return match;
	}
	for (int i = 0; i < 2048; i++) {
		const char *w = os_bip39_wordlist[i];
		size_t wl = strlen(w);
		if (strncmp(w, prefix, n) != 0)
			continue;
		if (wl == n) {
			if (exact >= 0)
				return -1;   /* two words equal the prefix */
			exact = i;
		} else {
			return -1;         /* still extendable: not complete yet */
		}
	}
	return exact;
}

const char *os_bip39_word_at(int index)
{
	if (index < 0 || index >= 2048)
		return NULL;
	return os_bip39_wordlist[index];
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
