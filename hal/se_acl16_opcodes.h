/*
 * HardID Hardware Wallet — ACL16 APDU opcodes
 * Copyright (C) 2026 LightningASIC / HardID contributors
 * License: Apache License 2.0
 *
 * PLACEHOLDER opcodes. Replace with the real values from the ACL16
 * datasheet (vendor NDA). Keeping them in one header means the entire
 * command set is updated in a single file when documentation arrives.
 *
 * Convention: CLA 0x80 for proprietary ACL16 commands (typical for SE
 * vendors); adjust to the datasheet's class byte.
 */

#ifndef HARDID_SE_ACL16_OPCODES_H
#define HARDID_SE_ACL16_OPCODES_H

/* Class byte for proprietary ACL16 commands */
#define ACL16_CLA            0x80

/* Instruction opcodes (PLACEHOLDERS — confirm against datasheet) */
#define ACL16_INS_GET_RANDOM     0x84   /* like GP GET CHALLENGE; confirm */
#define ACL16_INS_STORE_SEED     0xD0   /* PLACEHOLDER */
#define ACL16_INS_IS_INIT        0xD2   /* PLACEHOLDER */
#define ACL16_INS_SIGN           0xD4   /* PLACEHOLDER */
#define ACL16_INS_GET_XPUB       0xD6   /* PLACEHOLDER */
#define ACL16_INS_VERIFY_PIN     0x20   /* like ISO VERIFY; confirm */
#define ACL16_INS_POLICY_AUTH    0xD8   /* PLACEHOLDER */
#define ACL16_INS_MONO_READ      0xDA   /* PLACEHOLDER */
#define ACL16_INS_MONO_INC       0xDC   /* PLACEHOLDER */
#define ACL16_INS_ATTEST         0xDE   /* PLACEHOLDER */

/* P1 selectors for sign/get_xpub curve + path encoding */
#define ACL16_P1_CURVE_SECP256K1 0x01   /* PLACEHOLDER — CONFIRM ACL16 supports
                                         * secp256k1 natively (audit gate) */

#endif /* HARDID_SE_ACL16_OPCODES_H */
