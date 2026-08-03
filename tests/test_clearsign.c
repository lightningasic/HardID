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
		printf("PASS t5 eip-1559 transfer parsed\n");
	}

	/* 6 malformed input -> -1 */
	if (os_clearsign_parse_evm((const uint8_t *)"\x01\x02", 2, &it) == 0) { printf("FAIL t6\n"); return 1; }
	printf("PASS t6 malformed rejected\n");

	printf("\nALL CLEARSIGN TESTS PASSED\n");
	return 0;
}
