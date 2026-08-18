/*
 * HardID Hardware Wallet — U2F (CTAP1) compatibility shim
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Legacy RPs and Chrome's "security key" (2FA) flow drive CTAP1 U2F over
 * CTAPHID_MSG (GitHub security-key registration is one). The device is
 * CTAP2-native; this shim maps the two U2F operations onto the same
 * SE-bound credential system used by CTAP2 (the 21-byte self-describing
 * credID works as a U2F key handle unchanged):
 *
 *   U2F_REGISTER     -> create credential, return pubkey||keyHandle||
 *                       attestation cert||attestation signature
 *   U2F_AUTHENTICATE -> tag-check the key handle, then sign (enforce) or
 *                       answer 0x6985 (check-only probe)
 *
 * Wire format (U2F v1.2):
 *   register req:  CLA=0 INS=1 P1 P2 00 Lc(2) | challenge(32) appid(32)
 *   register resp: 05 || pubkey(65) || khLen(1) || kh || cert || sig || 9000
 *     sig = attKey sign( 00 || appid || challenge || kh || pubkey )
 *   auth req:      CLA=0 INS=2 P1 P2 00 Lc(2) | challenge(32) appid(32)
 *                  || khLen(1) || kh
 *   auth resp:     UP(1) || counter(4 BE) || sig(64) || 9000
 *     sig = credKey sign( appid || UP || counter || challenge )
 *   status words:  6985 conditions (presence required), 6A80 wrong data,
 *                  9000 ok
 */

#ifndef HARDID_FIDO_U2F_H
#define HARDID_FIDO_U2F_H

#include <stdint.h>
#include <stddef.h>

/* Dispatch one U2F APDU; writes the APDU response (data || SW1SW2). */
void fido_u2f_handle(const uint8_t *apdu, size_t apdu_len,
                     uint8_t *out, size_t out_cap, size_t *out_len);

#endif /* HARDID_FIDO_U2F_H */
