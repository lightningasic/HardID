/* Clear Sign EVM parser tests. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/clearsign.h"

/* helper to build RLP string/list header */
static size_t rlp_hdr(uint8_t *out, int is_list, size_t l)
{
	uint8_t base = is_list ? 0xc0 : 0x80;
	if (l < 56) { out[0] = base + l; return 1; }
	if (l < 256) { out[0] = base + 55 + 1; out[1] = l; return 2; }
	out[0] = base + 55 + 2; out[1] = l >> 8; out[2] = l & 0xff; return 3;
}
static size_t rlp_str(uint8_t *out, const uint8_t *d, size_t l)
{
	size_t h = rlp_hdr(out, 0, l);
	memcpy(out + h, d, l);
	return h + l;
}
static size_t rlp_u(uint8_t *out, uint64_t v)
{
	uint8_t b[8]; int n = 0;
	if (v == 0) { out[0] = 0x80; return 1; }
	while (v) { b[7 - n++] = v & 0xff; v >>= 8; }
	return rlp_str(out, b + 8 - n, n);
}

/* build a legacy tx: nonce, gasPrice, gasLimit, to, value, data */
static size_t build_legacy(uint8_t *out, uint64_t gasPrice, uint64_t gasLimit,
                           const uint8_t to[20], uint64_t value,
                           const uint8_t *data, size_t dlen)
{
	uint8_t tmp[1024]; size_t o = 0;
	o += rlp_u(tmp + o, 1);
	o += rlp_u(tmp + o, gasPrice);
	o += rlp_u(tmp + o, gasLimit);
	if (to) o += rlp_str(tmp + o, to, 20); else { tmp[o++] = 0x80; }
	o += rlp_u(tmp + o, value);
	o += rlp_str(tmp + o, data, dlen);
	size_t h = rlp_hdr(out, 1, o);
	memcpy(out + h, tmp, o);
	return h + o;
}

#include "../core/keccak.c"
#include "../core/hkdf.c"
#include "../core/psbt.c"
#include "../core/base58.c"
#include "../core/clearsign.c"

int main(void)
{
	uint8_t buf[2048]; os_tx_intent it;
	uint8_t to[20];
	for (int i = 0; i < 20; i++) to[i] = 0x10 + i;

	/* 1 plain ETH transfer */
	size_t n = build_legacy(buf, 20, 21000, to, 1000, NULL, 0);
	if (os_clearsign_parse_evm(buf, n, &it) != 0) { printf("FAIL t1 parse\n"); return 1; }
	if (it.kind != OS_INTENT_TRANSFER || it.risk != OS_RISK_LOW) { printf("FAIL t1 kind=%d\n", it.kind); return 1; }
	if (it.amount != 1000 || it.fee_limit != 20ull*21000) { printf("FAIL t1 amount/fee\n"); return 1; }
	if (strncmp(it.to, "0x", 2) != 0 || strlen(it.to) != 42) { printf("FAIL t1 addr\n"); return 1; }
	printf("PASS t1 plain transfer parsed\n");

	/* 2 ERC20 approve with unlimited amount -> HIGH risk */
	uint8_t cd[4 + 32 + 32];
	memcpy(cd, "\x09\x5e\xa7\xb3", 4);
	memset(cd + 4, 0, 12); /* addr pad */
	memcpy(cd + 4 + 12, to, 20);
	memset(cd + 4 + 32, 0xff, 32); /* unlimited */
	n = build_legacy(buf, 20, 50000, to, 0, cd, sizeof cd);
	os_clearsign_parse_evm(buf, n, &it);
	if (it.kind != OS_INTENT_ERC20_APPROVE || !it.unlimited_approval || it.risk != OS_RISK_HIGH) {
		printf("FAIL t2 kind=%d unlim=%d risk=%d\n", it.kind, it.unlimited_approval, it.risk); return 1; }
	printf("PASS t2 unlimited approve flagged HIGH\n");

	/* 3 ERC20 transfer -> recognized, LOW */
	memcpy(cd, "\xa9\x05\x9c\xbb", 4);
	memset(cd + 4 + 32, 0, 32); /* small amount */
	n = build_legacy(buf, 20, 50000, to, 0, cd, sizeof cd);
	os_clearsign_parse_evm(buf, n, &it);
	if (it.kind != OS_INTENT_ERC20_TRANSFER || it.risk != OS_RISK_LOW) { printf("FAIL t3\n"); return 1; }
	printf("PASS t3 erc20 transfer recognized\n");

	/* 4 unknown selector -> UNKNOWN + data hash */
	memcpy(cd, "\xde\xad\xbe\xef", 4);
	n = build_legacy(buf, 20, 50000, to, 0, cd, sizeof cd);
	os_clearsign_parse_evm(buf, n, &it);
	if (it.kind != OS_INTENT_UNKNOWN || it.risk != OS_RISK_HIGH) { printf("FAIL t4 kind=%d\n", it.kind); return 1; }
	printf("PASS t4 unknown calldata -> UNKNOWN\n");

	/* 5 EIP-1559 (type 2) plain transfer */
	{
		uint8_t tmp[1024]; size_t o = 0;
		uint8_t inner[1024]; size_t io = 0;
		io += rlp_u(inner + io, 1);     /* chainId */
		io += rlp_u(inner + io, 1);     /* nonce */
		io += rlp_u(inner + io, 2);     /* maxPrio */
		io += rlp_u(inner + io, 30);    /* maxFee */
		io += rlp_u(inner + io, 21000); /* gasLimit */
		io += rlp_str(inner + io, to, 20);
		io += rlp_u(inner + io, 5000);  /* value */
		io += rlp_str(inner + io, NULL, 0); /* data */
		io += rlp_hdr(inner + io, 1, 0);    /* accessList: empty list */
		size_t h = rlp_hdr(tmp, 1, io);
		memcpy(tmp + h, inner, io);
		buf[0] = 0x02;
		memcpy(buf + 1, tmp, h + io);
		o = 1 + h + io;
		if (os_clearsign_parse_evm(buf, o, &it) != 0) { printf("FAIL t5 parse\n"); return 1; }
		if (it.kind != OS_INTENT_TRANSFER || it.amount != 5000 || it.fee_limit != 30ull*21000) {
			printf("FAIL t5 amt=%llu fee=%llu\n", (unsigned long long)it.amount, (unsigned long long)it.fee_limit); return 1; }
		if (it.chain_id != 1) { printf("FAIL t5 chain_id=%llu\n", (unsigned long long)it.chain_id); return 1; }
		printf("PASS t5 eip-1559 transfer parsed (chainId extracted)\n");
	}

	/* 6 malformed input -> -1 */
	if (os_clearsign_parse_evm((const uint8_t *)"\x01\x02", 2, &it) == 0) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 malformed rejected\n");

	/* 7 H1: a >8-byte scalar (9-byte value) must be REFUSED, never
	 * silently truncated to a fake small amount. Build a legacy tx whose
	 * value field is a 9-byte integer. */
	{
		uint8_t val9[9] = { 0x01, 0,0,0,0, 0,0,0,0 }; /* 1 followed by 8 zeros */
		uint8_t tmp[1024]; size_t o = 0;
		o += rlp_u(tmp + o, 1);
		o += rlp_u(tmp + o, 20);
		o += rlp_u(tmp + o, 21000);
		o += rlp_str(tmp + o, to, 20);
		o += rlp_str(tmp + o, val9, 9);    /* 9-byte value → must reject */
		o += rlp_str(tmp + o, NULL, 0);
		size_t h = rlp_hdr(buf, 1, o);
		memcpy(buf + h, tmp, o);
		if (os_clearsign_parse_evm(buf, h + o, &it) == 0) {
			printf("FAIL t7 oversized integer not refused\n"); return 1; }
		printf("PASS t7 oversized scalar refused (no truncating)\n");
	}

	/* 8 M3: transferFrom(from,to,value) — recipient is the SECOND word,
	 * amount the THIRD. The payer (first word) must NOT be shown as to. */
	{
		uint8_t from[20], rcpt[20];
		for (int i = 0; i < 20; i++) { from[i] = 0xa0 + i; rcpt[i] = 0xb0 + i; }
		uint8_t cd3[4 + 32 + 32 + 32];
		memcpy(cd3, "\x23\xb8\x72\xdd", 4);
		memset(cd3 + 4, 0, 12);            memcpy(cd3 + 4 + 12, from, 20);  /* word1: from */
		memset(cd3 + 4 + 32, 0, 12);       memcpy(cd3 + 4 + 32 + 12, rcpt, 20); /* word2: to */
		memset(cd3 + 4 + 64, 0, 31);       cd3[4 + 64 + 31] = 0x64;         /* word3: 100 */
		n = build_legacy(buf, 20, 50000, to, 0, cd3, sizeof cd3);
		if (os_clearsign_parse_evm(buf, n, &it) != 0) { printf("FAIL t8 parse\n"); return 1; }
		if (it.kind != OS_INTENT_ERC20_TRANSFER) { printf("FAIL t8 kind=%d\n", it.kind); return 1; }
		/* displayed recipient must be rcpt (word2), not from (word1) */
		if (strstr(it.to, "0xa0") != NULL) { printf("FAIL t8 showed payer as to: %s\n", it.to); return 1; }
		if (strcmp(it.amount_token, "100") != 0) { printf("FAIL t8 amount_token=%s\n", it.amount_token); return 1; }
		printf("PASS t8 transferFrom recipient/amount decoded correctly\n");
	}

	/* 9 M4: ERC20 transfer amount must surface in amount_token. */
	{
		uint8_t cd2[4 + 32 + 32];
		memcpy(cd2, "\xa9\x05\x9c\xbb", 4);
		memset(cd2 + 4, 0, 12); memcpy(cd2 + 4 + 12, to, 20);
		memset(cd2 + 4 + 32, 0, 30); cd2[4 + 32 + 30] = 0x01; cd2[4 + 32 + 31] = 0xf4; /* 500 */
		n = build_legacy(buf, 20, 50000, to, 0, cd2, sizeof cd2);
		if (os_clearsign_parse_evm(buf, n, &it) != 0) { printf("FAIL t9 parse\n"); return 1; }
		if (strcmp(it.amount_token, "500") != 0) { printf("FAIL t9 amount_token=%s\n", it.amount_token); return 1; }
		printf("PASS t9 token amount surfaced in amount_token\n");
	}

	/* 10 M1: legacy tx with EIP-155 v -> chain_id recovered. v=37+2*56+1
	 * is chain 56 (BSC); build a legacy tx with explicit v/r/s so the
	 * parser can recover chain_id = (v-35)/2 = 56. */
	{
		uint8_t tmp[1024]; size_t o = 0;
		o += rlp_u(tmp + o, 1);            /* nonce */
		o += rlp_u(tmp + o, 20);           /* gasPrice */
		o += rlp_u(tmp + o, 21000);        /* gasLimit */
		o += rlp_str(tmp + o, to, 20);     /* to */
		o += rlp_u(tmp + o, 1000);         /* value */
		o += rlp_str(tmp + o, NULL, 0);    /* data */
		o += rlp_u(tmp + o, 35 + 2*56 + 1);/* v = 148 -> chain 56 */
		o += rlp_u(tmp + o, 1);            /* r (dummy) */
		o += rlp_u(tmp + o, 2);            /* s (dummy) */
		size_t h = rlp_hdr(buf, 1, o);
		memcpy(buf + h, tmp, o);
		if (os_clearsign_parse_evm(buf, h + o, &it) != 0) { printf("FAIL t10 parse\n"); return 1; }
		if (it.chain_id != 56) { printf("FAIL t10 chain_id=%llu\n", (unsigned long long)it.chain_id); return 1; }
		printf("PASS t10 legacy EIP-155 chain_id recovered\n");
	}

	/* 11 M2: EIP-2930 (type 0x01) fields in the right order, not misread
	 * as legacy. chainId=1, gasPrice=20, gasLimit=21000, value=777. */
	{
		uint8_t inner[1024]; size_t io = 0;
		io += rlp_u(inner + io, 1);        /* chainId */
		io += rlp_u(inner + io, 1);        /* nonce */
		io += rlp_u(inner + io, 20);       /* gasPrice */
		io += rlp_u(inner + io, 21000);    /* gasLimit */
		io += rlp_str(inner + io, to, 20); /* to */
		io += rlp_u(inner + io, 777);      /* value */
		io += rlp_str(inner + io, NULL, 0);/* data */
		io += rlp_hdr(inner + io, 1, 0);   /* accessList: empty list */
		size_t h = rlp_hdr(buf + 1, 1, io);
		memcpy(buf + 1 + h, inner, io);
		buf[0] = 0x01;
		size_t n2 = 1 + h + io;
		if (os_clearsign_parse_evm(buf, n2, &it) != 0) { printf("FAIL t11 parse\n"); return 1; }
		if (it.chain_id != 1 || it.amount != 777 || it.fee_limit != 20ull*21000) {
			printf("FAIL t11 chain=%llu amt=%llu fee=%llu\n",
			       (unsigned long long)it.chain_id, (unsigned long long)it.amount,
			       (unsigned long long)it.fee_limit); return 1; }
		printf("PASS t11 eip-2930 parsed in correct field order\n");
	}

	printf("\nALL CLEARSIGN TESTS PASSED\n");
	return 0;
}
