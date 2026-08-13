/* Host-side tx assembly tests — EVM v/r/s + BTC DER/witness. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/tx_asm.h"

#include "../core/hkdf.c"
#include "../core/rfc6979.c"
#include "../core/secp256k1.c"
#include "../core/ecdsa.c"
#include "../core/tx_asm.c"

static size_t unhex(const char *s, uint8_t *out)
{
	size_t n = 0;
	while (s[0] && s[1]) { unsigned v; sscanf(s, "%2x", &v); out[n++] = (uint8_t)v; s += 2; }
	return n;
}

/* Minimal strict DER decoder for the round-trip check: parses
 * 0x30 len 0x02 rlen r 0x02 slen s [trailing sighash byte], returns
 * r||s (64 bytes) and the trailing byte. */
static int der_decode(const uint8_t *d, size_t n, uint8_t rs64[64], uint8_t *trail)
{
	if (!d || n < 8 || d[0] != 0x30)
		return -1;
	if ((size_t)d[1] + 2 != n || d[2] != 0x02)
		return -1;
	size_t rlen = d[3];
	if (4 + rlen >= n)
		return -1;
	const uint8_t *r = d + 4;
	size_t so = 4 + rlen;
	if (d[so] != 0x02)
		return -1;
	size_t slen = d[so + 1];
	if (so + 2 + slen + 1 != n)
		return -1;
	const uint8_t *s = d + so + 2;
	memset(rs64, 0, 64);
	if (rlen > 33 || slen > 33)
		return -1;
	if (rlen == 33) { if (r[0] != 0) return -1; r++; rlen--; }
	if (slen == 33) { if (s[0] != 0) return -1; s++; slen--; }
	memcpy(rs64 + (32 - rlen), r, rlen);
	memcpy(rs64 + 32 + (32 - slen), s, slen);
	*trail = d[so + 2 + slen];
	return 0;
}

int main(void)
{
	uint8_t sig[64], rs[64], out[128], trail;
	size_t olen;

	/* ---- t1: EVM v/r/s assembly ---- */
	memset(sig, 0, 64); sig[0] = 0xaa; sig[32] = 0xbb;
	if (os_evm_sig_assemble(1, sig, 0, out, sizeof(out), &olen) != 0 || olen != 65 || out[64] != 37) { printf("FAIL t1a olen=%zu v=%u\n", olen, out[64]); return 1; }
	if (os_evm_sig_assemble(1, sig, 1, out, sizeof(out), &olen) != 0 || out[64] != 38) { printf("FAIL t1b\n"); return 1; }
	/* POLYGON chain_id=137 → v=309 = 0x0135 (two-byte v) */
	if (os_evm_sig_assemble(137, sig, 0, out, sizeof(out), &olen) != 0 || olen != 66 || out[64] != 0x01 || out[65] != 0x35) { printf("FAIL t1c olen=%zu\n", olen); return 1; }
	if (os_evm_sig_assemble(137, sig, 1, out, sizeof(out), &olen) != 0 || out[65] != 0x36) { printf("FAIL t1d\n"); return 1; }
	if (os_evm_sig_assemble(1, sig, 2, out, sizeof(out), &olen) == 0) { printf("FAIL t1e recid>1\n"); return 1; }
	/* buffer too small for the 2-byte v */
	uint8_t small[65];
	if (os_evm_sig_assemble(137, sig, 0, small, sizeof(small), &olen) == 0) { printf("FAIL t1f small buf\n"); return 1; }
	if (memcmp(out, sig, 64) != 0) { printf("FAIL t1g r||s passthrough\n"); return 1; }
	printf("PASS t1 EVM v/r/s assemble\n");

	/* ---- t2: DER hand-vector r=1, s=2 ---- */
	memset(sig, 0, 64); sig[31] = 0x01; sig[63] = 0x02;
	if (os_btc_sig_to_der(sig, OS_BTC_SIGHASH_ALL, out, sizeof(out), &olen) != 0) { printf("FAIL t2\n"); return 1; }
	const uint8_t exp[] = { 0x30,0x07,0x02,0x01,0x01,0x02,0x01,0x02,0x01 };
	if (olen != sizeof(exp) || memcmp(out, exp, sizeof(exp)) != 0) { printf("FAIL t2 der bytes\n"); return 1; }
	printf("PASS t2 DER hand-vector\n");

	/* ---- t3: DER round-trip via real sign ---- */
	uint8_t priv[32]; memset(priv, 0, 32); priv[31] = 7;
	uint8_t hash[32]; unhex("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", hash);
	uint8_t real_pub[33];
	if (os_secp256k1_pubkey(priv, real_pub) != 0) { printf("FAIL t3 pub\n"); return 1; }
	if (os_ecdsa_sign(priv, hash, sig) != 0) { printf("FAIL t3 sign\n"); return 1; }
	if (os_ecdsa_verify(real_pub, hash, sig) != 1) { printf("FAIL t3 verify\n"); return 1; }
	if (os_btc_sig_to_der(sig, OS_BTC_SIGHASH_ALL, out, sizeof(out), &olen) != 0) { printf("FAIL t3 der\n"); return 1; }
	if (der_decode(out, olen, rs, &trail) != 0) { printf("FAIL t3 decode\n"); return 1; }
	if (memcmp(rs, sig, 64) != 0) { printf("FAIL t3 roundtrip\n"); return 1; }
	if (trail != OS_BTC_SIGHASH_ALL) { printf("FAIL t3 trail\n"); return 1; }
	printf("PASS t3 DER sign+encode+decode roundtrip\n");

	/* ---- t4: low-s normalization (force high-s: s = n-1) ---- */
	uint8_t n_be[32];
	unhex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", n_be);
	memset(sig, 0, 64); sig[31] = 0x01;               /* r = 1 */
	memcpy(sig + 32, n_be, 32);                        /* s = n (== 0 mod n, invalid) */
	sig[63] -= 1;                                      /* s = n - 1 (high) */
	if (os_btc_sig_to_der(sig, OS_BTC_SIGHASH_ALL, out, sizeof(out), &olen) != 0) { printf("FAIL t4\n"); return 1; }
	if (der_decode(out, olen, rs, &trail) != 0) { printf("FAIL t4 decode\n"); return 1; }
	if (rs[63] != 0x01) { printf("FAIL t4 low-s not normalized\n"); return 1; }
	for (int i = 0; i < 31; i++) if (rs[32 + i] != 0) { printf("FAIL t4 low-s pad\n"); return 1; }
	printf("PASS t4 low-s normalization\n");

	/* ---- t5: witness stack layout (fresh low-s signature) ---- */
	if (os_ecdsa_sign(priv, hash, sig) != 0) { printf("FAIL t5 sign\n"); return 1; }
	if (os_btc_witness_p2wpkh(sig, OS_BTC_SIGHASH_ALL, real_pub, out, sizeof(out), &olen) != 0) { printf("FAIL t5\n"); return 1; }
	if (out[0] != 2) { printf("FAIL t5 count\n"); return 1; }
	size_t siglen = out[1];
	if (siglen < 8 || siglen > 73) { printf("FAIL t5 siglen=%zu\n", siglen); return 1; }
	if (out[2 + siglen] != 33) { printf("FAIL t5 publen\n"); return 1; }
	if (memcmp(out + 3 + siglen, real_pub, 33) != 0) { printf("FAIL t5 pub bytes\n"); return 1; }
	if (olen != 3 + siglen + 33) { printf("FAIL t5 total=%zu\n", olen); return 1; }
	if (der_decode(out + 2, siglen, rs, &trail) != 0) { printf("FAIL t5 sig decode\n"); return 1; }
	if (memcmp(rs, sig, 64) != 0) { printf("FAIL t5 sig roundtrip\n"); return 1; }
	printf("PASS t5 P2WPKH witness layout\n");

	/* ---- t6: buffer-too-small rejection ---- */
	uint8_t tiny[4];
	if (os_btc_witness_p2wpkh(sig, OS_BTC_SIGHASH_ALL, real_pub, tiny, sizeof(tiny), &olen) == 0) { printf("FAIL t6 small buf\n"); return 1; }
	printf("PASS t6 witness overflow guard\n");

	printf("ALL PASS\n");
	return 0;
}
