/*
 * HardID Hardware Wallet — host-side transaction assembly
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * The device signs and returns COMPACT signatures only (r||s, 64 bytes)
 * plus a recovery id — it never returns a serialized tx. The final
 * on-chain serialization (EVM v/r/s; BTC DER + witness) is assembled on
 * the HOST from those compact signatures. These helpers are that host-side
 * assembly step, written so any host wallet integration can reuse them
 * instead of re-implementing the (subtle, consensus-critical) encodings.
 *
 * See docs/04 §3.3 and docs/07 ("签名的最终组装在主机侧完成").
 */

#ifndef HARDID_TX_ASM_H
#define HARDID_TX_ASM_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SIGHASH_ALL — the only sighash type the device signs (see psbt.c). */
#define OS_BTC_SIGHASH_ALL 0x01

/*
 * EVM: assemble the final signature r(32) || s(32) || v from the device's
 * compact r||s + recovery id.
 *
 * EIP-155 legacy: v = 35 + 2*chain_id + recovery_id. v is emitted as a
 * MINIMAL big-endian integer (1..4 bytes) because a high chain_id (e.g.
 * POLYGON=137 → v=309) does not fit one byte. r and s are copied verbatim.
 *
 *   chain_id  — EIP-155 chain id (os_evm_chain_id_for_coin).
 *   sig64     — compact r||s from the SE.
 *   recid     — recovery id 0 or 1.
 *   out/out_max — output buffer (68 bytes covers the worst case
 *                 64 + 4-byte v); out_len receives 64 + v_len.
 *
 * Returns 0 on success, -1 on invalid input (recid > 1) or a buffer too
 * small for the encoded v.
 */
int os_evm_sig_assemble(uint32_t chain_id,
                        const uint8_t sig64[64], uint8_t recid,
                        uint8_t *out, size_t out_max, size_t *out_len);

/*
 * BTC: convert a compact r||s into a DER-encoded signature and append the
 * sighash type byte (SIGHASH_ALL). DER structure:
 *
 *   0x30 <total-len> 0x02 <r-len> r... 0x02 <s-len> s... <sighash_type>
 *
 * s is normalized to low-s (BIP62) defensively: the SE contract does not
 * guarantee low-s, but Bitcoin consensus/standardness rejects high-s, and
 * the recovery id is not used on the BTC side so re-normalizing s cannot
 * invalidate anything. r is left untouched.
 *
 *   sig64        — compact r||s from the SE.
 *   sighash_type — SIGHASH_ALL (OS_BTC_SIGHASH_ALL).
 *   out/out_max  — output buffer (72 bytes is enough for the worst case
 *                  72-byte DER + 1 sighash byte = 73).
 *   out_len      — receives the actual length.
 *
 * Returns 0 on success, -1 if the buffer is too small.
 */
int os_btc_sig_to_der(const uint8_t sig64[64], uint8_t sighash_type,
                      uint8_t *out, size_t out_max, size_t *out_len);

/*
 * BTC: build the witness stack for a native P2WPKH (SegWit v0, 20-byte
 * program) input. The stack is the serialized witness as it appears in a
 * signed transaction:
 *
 *   <count=2> <len(sig)> sig(DER+sighash) <len(pub)=33> pubkey
 *
 * where each length is a Bitcoin CompactSize varint.
 *
 *   pub33        — the compressed public key for this input (host derives it
 *                  from the xpub/path, or the device may return it alongside
 *                  the signature).
 *
 * Returns 0 on success, -1 if the buffer is too small (worst case 1 + 1 + 73
 * + 1 + 33 = 109 bytes).
 */
int os_btc_witness_p2wpkh(const uint8_t sig64[64], uint8_t sighash_type,
                          const uint8_t pub33[33],
                          uint8_t *out, size_t out_max, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_TX_ASM_H */
