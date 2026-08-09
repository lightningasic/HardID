/*
 * HardID Hardware Wallet — Clear Sign engine (EVM)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * Minimal RLP decode sufficient to extract intent from legacy (type 0) and
 * EIP-1559 (type 2) EVM transactions. Deliberately strict: on any deviation
 * from expected structure it degrades to UNKNOWN rather than guessing.
 */

#include "clearsign.h"
#include "keccak.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>

/* ---- tiny RLP reader ---- */typedef struct {
	const uint8_t *p;
	size_t len;
} rlp;

typedef struct {
	const uint8_t *ptr;   /* payload start (after header) */
	size_t len;           /* payload length */
	int is_list;          /* 1 = list, 0 = string */
	size_t total;         /* header + payload bytes consumed */
} rlp_item;

static int rlp_read(rlp *r, rlp_item *it)
{
	if (r->len == 0)
		return -1;
	uint8_t b0 = r->p[0];
	size_t hdr, l;
	int is_list;

	if (b0 < 0x80)      { it->ptr = r->p; it->len = 1; it->is_list = 0; it->total = 1; goto done; }
	if (b0 < 0xb8)      { l = b0 - 0x80; hdr = 1; is_list = 0; goto str; }
	if (b0 < 0xc0)      { /* long string */
		uint8_t ll = b0 - 0xb7;
		if (ll > 4 || r->len < 1u + ll) return -1;
		l = 0;
		for (uint8_t i = 0; i < ll; i++) l = (l << 8) | r->p[1 + i];
		hdr = 1 + ll; is_list = 0; goto str;
	}
	if (b0 < 0xf8)      { l = b0 - 0xc0; hdr = 1; is_list = 1; goto str; }
	/* long list */
	{
		uint8_t ll = b0 - 0xf7;
		if (ll > 4 || r->len < 1u + ll) return -1;
		l = 0;
		for (uint8_t i = 0; i < ll; i++) l = (l << 8) | r->p[1 + i];
		hdr = 1 + ll; is_list = 1;
	}
str:
	if (r->len < hdr + l)
		return -1;
	it->ptr = r->p + hdr;
	it->len = l;
	it->is_list = is_list;
	it->total = hdr + l;
done:
	r->p += it->total;
	r->len -= it->total;
	return 0;
}

/* interpret an RLP string as uint64 (big-endian, <=8 bytes) */
static uint64_t rlp_u64(const rlp_item *it)
{
	uint64_t v = 0;
	size_t n = it->len > 8 ? 8 : it->len;
	for (size_t i = 0; i < n; i++)
		v = (v << 8) | it->ptr[i];
	return v;
}

static void to_hex0x(const uint8_t *addr20, char *out /*>=43*/)
{
	/* EIP-55 mixed-case checksum address (keccak-based). */
	os_eth_address_checksum(addr20, out);
}

/* 4-byte selectors we can name */
const char *os_clearsign_method_name(const uint8_t s[4])
{
	static const struct { uint8_t s[4]; const char *name; } tbl[] = {
		{ {0xa9,0x05,0x9c,0xbb}, "transfer(address,uint256)" }, /* a9059cbb */
		{ {0x09,0x5e,0xa7,0xb3}, "approve(address,uint256)" },  /* 095ea7b3 */
		{ {0x23,0xb8,0x72,0xdd}, "transferFrom(...)" },          /* 23b872dd */
	};
	for (size_t i = 0; i < sizeof(tbl)/sizeof(tbl[0]); i++)
		if (memcmp(s, tbl[i].s, 4) == 0)
			return tbl[i].name;
	return NULL;
}

bool os_clearsign_is_unlimited_amount(const uint8_t a[32])
{
	for (int i = 0; i < 32; i++)
		if (a[i] != 0xff)
			return false;
	return true;
}

/* decode calldata for ERC20 transfer/approve to fill intent */
static void decode_erc20(const uint8_t *data, size_t dlen, os_tx_intent *o)
{
	/* must have at least the 4-byte selector before any memcmp */
	if (dlen < 4) {
		o->kind = OS_INTENT_UNKNOWN;
		o->risk = OS_RISK_HIGH;
		os_keccak256(data, dlen, o->data_hash);
		return;
	}
	const char *m = os_clearsign_method_name(data);
	if (!m || dlen < 4 + 32 + 32) {
		o->kind = OS_INTENT_UNKNOWN;
		o->risk = OS_RISK_HIGH;
		os_keccak256(data, dlen, o->data_hash);
		return;
	}
	/* args: [32-byte addr][32-byte amount] */
	const uint8_t *addr = data + 4 + 12; /* last 20 bytes of first word */
	const uint8_t *amt  = data + 4 + 32;

	if (memcmp(data, "\xa9\x05\x9c\xbb", 4) == 0) { /* transfer */
		o->kind = OS_INTENT_ERC20_TRANSFER;
		o->risk = OS_RISK_LOW;
	} else if (memcmp(data, "\x09\x5e\xa7\xb3", 4) == 0) { /* approve */
		o->kind = OS_INTENT_ERC20_APPROVE;
		o->risk = OS_RISK_MEDIUM;
		if (os_clearsign_is_unlimited_amount(amt)) {
			o->unlimited_approval = true;
			o->risk = OS_RISK_HIGH;
		}
	} else {
		o->kind = OS_INTENT_CONTRACT_CALL;
		o->risk = OS_RISK_MEDIUM;
	}
	to_hex0x(addr, o->to);        /* token recipient/spender */
	snprintf(o->method, sizeof o->method, "%s", m);
	/* token amount: UI formats; hash raw 32-byte word for audit */
	os_keccak256(amt, 32, o->data_hash);
}

int os_clearsign_parse_evm(const uint8_t *raw, size_t len, os_tx_intent *o)
{
	rlp r = { raw, len }, body;
	rlp_item top;
	int typed = 0;

	memset(o, 0, sizeof *o);
	o->chain = OS_CHAIN_ETH;
	o->kind = OS_INTENT_UNKNOWN;
	o->risk = OS_RISK_HIGH;

	if (len == 0)
		return -1;

	/* typed tx envelope (EIP-2718): first byte 0x01/0x02 then RLP list */
	if (raw[0] == 0x01 || raw[0] == 0x02) {
		typed = raw[0];
		r.p = raw + 1;
		r.len = len - 1;
	}

	if (rlp_read(&r, &top) != 0 || !top.is_list)
		return -1;
	body.p = top.ptr;
	body.len = top.len;

	/* Field order (legacy): nonce, gasPrice, gasLimit, to, value, data, ...
	 * Field order (1559):  chainId, nonce, maxPrio, maxFee, gasLimit, to, value, data, accessList,... */
	uint64_t maxfee = 0, gaslimit = 0;

	if (typed == 2) {
		/* skip chainId(0), nonce(1), maxPrio(2), capture maxFee(3), gasLimit(4) */
		rlp_item f;
		for (int i = 0; i <= 4; i++) {
			if (rlp_read(&body, &f) != 0) return -1;
			if (i == 3) maxfee = rlp_u64(&f);
			if (i == 4) gaslimit = rlp_u64(&f);
		}
	} else {
		rlp_item f;
		for (int i = 0; i <= 2; i++) { /* nonce, gasPrice, gasLimit */
			if (rlp_read(&body, &f) != 0) return -1;
			if (i == 1) maxfee = rlp_u64(&f);
			if (i == 2) gaslimit = rlp_u64(&f);
		}
	}
	/* fee_limit = maxfee * gaslimit, saturated: a malicious huge maxFee must
	 * not wrap into a small displayed fee. Clamp to UINT64_MAX on overflow. */
	if (gaslimit != 0 && maxfee > UINT64_MAX / gaslimit)
		o->fee_limit = UINT64_MAX;
	else
		o->fee_limit = maxfee * gaslimit;

	/* to */
	rlp_item to, val, dat;
	if (rlp_read(&body, &to) != 0) return -1;
	if (rlp_read(&body, &val) != 0) return -1;
	if (rlp_read(&body, &dat) != 0) return -1;

	o->amount = rlp_u64(&val);

	if (to.len == 20) {
		to_hex0x(to.ptr, o->to);
	} else if (to.len == 0) {
		/* contract creation */
		snprintf(o->to, sizeof o->to, "(contract creation)");
		o->kind = OS_INTENT_CONTRACT_CALL;
		o->risk = OS_RISK_MEDIUM;
		snprintf(o->method, sizeof o->method, "deploy");
		return 0;
	} else {
		return -1;
	}

	if (dat.len == 0) {
		/* plain native transfer */
		o->kind = OS_INTENT_TRANSFER;
		o->risk = OS_RISK_LOW;
		o->method[0] = 0;
		return 0;
	}

	/* contract interaction */
	decode_erc20(dat.ptr, dat.len, o);
	if (o->kind == OS_INTENT_UNKNOWN) {
		/* keep recipient address; data_hash already set */
	}
	return 0;
}

/* ---- legacy tx builder (RLP) ---- */

/* RLP single uint64, returns bytes written. */
static size_t rlp_uint(uint8_t *out, uint64_t v)
{
	if (v < 0x80) { out[0] = (uint8_t)v; return 1; }
	uint8_t be[8]; size_t nb = 0;
	while (v) { be[7 - nb] = (uint8_t)(v & 0xff); v >>= 8; nb++; }
	out[0] = (uint8_t)(0x80 + nb);
	memcpy(out + 1, be + (8 - nb), nb);
	return 1 + nb;
}

size_t os_clearsign_build_demo_legacy(uint8_t *out, uint64_t gasPrice,
                                      uint64_t gasLimit,
                                      const uint8_t to[20], uint64_t value)
{
	uint8_t body[64]; size_t o = 0;
	o += rlp_uint(body + o, 1);               /* nonce */
	o += rlp_uint(body + o, gasPrice);        /* gasPrice */
	o += rlp_uint(body + o, gasLimit);        /* gasLimit */
	body[o++] = (uint8_t)(0x80 + 20);         /* 20-byte to */
	memcpy(body + o, to, 20); o += 20;
	o += rlp_uint(body + o, value);           /* value */
	body[o++] = 0x80;                         /* empty data */
	if (o < 56) {
		out[0] = (uint8_t)(0xc0 + o);         /* short list header */
		memcpy(out + 1, body, o);
		return 1 + o;
	}
	return 0;
}
