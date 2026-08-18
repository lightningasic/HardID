/* CTAPHID framing tests (design doc 09 §7: INIT/CONT state machine, errors). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/fido_ctaphid.h"

#include "../core/fido_ctaphid.c"

/* count PASS/FAIL for the summary */
static int npass, nfail;
#define CHECK(cond, name) do { \
	if (cond) { npass++; printf("PASS %s\n", name); } \
	else { nfail++; printf("FAIL %s\n", name); } \
} while (0)

/* Build an INIT packet. */
static void mk_init(uint32_t cid, uint8_t cmd, uint16_t bcnt,
                    const uint8_t *data, uint16_t dlen, uint8_t p[64])
{
	memset(p, 0, 64);
	p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
	p[4] = cmd | 0x80;
	p[5] = bcnt >> 8; p[6] = bcnt;
	if (dlen) memcpy(p + 7, data, dlen < 57 ? dlen : 57);
}

static void mk_cont(uint32_t cid, uint8_t seq, const uint8_t *data,
                    uint16_t dlen, uint8_t p[64])
{
	memset(p, 0, 64);
	p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
	p[4] = seq & 0x7f;
	if (dlen) memcpy(p + 5, data, dlen < 59 ? dlen : 59);
}

/* Init exchange: reset state machine, run INIT on broadcast, return the
 * negotiated channel id. */
static uint32_t do_init(ctaphid_t *h, uint8_t (*out)[64])
{
	uint8_t nonce[8] = {0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33};
	uint8_t pkt[64];
	ctaphid_init(h);
	mk_init(0xffffffff, CTAPHID_INIT, 8, nonce, 8, pkt);
	ctaphid_feed(h, pkt, out, 200);
	uint32_t cid = ((uint32_t)out[0][15] << 24) | ((uint32_t)out[0][16] << 16) |
	               ((uint32_t)out[0][17] << 8) | out[0][18];
	return cid;
}

int main(void)
{
	ctaphid_t h;
	uint8_t out[200][64];
	uint8_t pkt[64];
	int n;

	/* ---- t1 INIT nonce echo + CID allocation ---- */
	uint32_t cid = do_init(&h, out);
	CHECK(out[0][4] == (CTAPHID_INIT | 0x80), "t1 init cmd byte");
	CHECK(out[0][7] == 0xde && out[0][14] == 0x33, "t1 nonce echoed");
	CHECK(cid != 0 && cid != 0xffffffff, "t1 cid allocated nonzero");
	CHECK(h.cid == cid, "t1 cid stored");
	/* payload: nonce(8)||cid(4)||proto(1)||major(1)||minor(1)||build(1)||caps(1) */
	CHECK(out[0][19] == CTAPHID_PROTOCOL_VERSION, "t1 protocol version");
	CHECK(out[0][23] == (CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG), "t1 capabilities");
	uint16_t bcnt = (uint16_t)((out[0][5] << 8) | out[0][6]);
	CHECK(bcnt == 17, "t1 init response length 17");

	/* ---- t2 ping echo (single packet) ---- */
	mk_init(cid, CTAPHID_PING, 5, (const uint8_t *)"hello", 5, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1, "t2 ping one packet");
	CHECK(out[0][4] == (CTAPHID_PING | 0x80), "t2 ping cmd");
	CHECK(memcmp(out[0] + 7, "hello", 5) == 0, "t2 ping echo");

	/* ---- t3 multi-packet reassembly: 57+59+59 > max INIT payload ---- */
	uint8_t big[120];
	for (int i = 0; i < 120; i++) big[i] = (uint8_t)i;
	mk_init(cid, CTAPHID_PING, 120, big, 57, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 0, "t3 awaiting CONT");
	mk_cont(cid, 0, big + 57, 59, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 0, "t3b still awaiting CONT (120 > 57+59=116)");
	mk_cont(cid, 1, big + 116, 4, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 3, "t3 response spans 3 packets");
	/* reassemble response */
	uint8_t rbuf[130];
	uint16_t rlen = (uint16_t)((out[0][5] << 8) | out[0][6]);
	memcpy(rbuf, out[0] + 7, 57);
	memcpy(rbuf + 57, out[1] + 5, 59);
	memcpy(rbuf + 116, out[2] + 5, 4);
	CHECK(rlen == 120 && memcmp(rbuf, big, 120) == 0, "t3 ping echo intact");

	/* ---- t3c incremental drain: long response with max_out=1 ---- */
	cid = do_init(&h, out);
	mk_init(cid, CTAPHID_PING, 120, big, 57, pkt);
	ctaphid_feed(&h, pkt, out, 200);
	mk_cont(cid, 0, big + 57, 59, pkt);
	ctaphid_feed(&h, pkt, out, 200);
	mk_cont(cid, 1, big + 116, 4, pkt);
	n = ctaphid_feed(&h, pkt, out, 1);   /* first response packet only */
	CHECK(n == 1, "t3c drain step 1");
	n = ctaphid_feed(&h, NULL, out, 1);
	CHECK(n == 1, "t3c drain step 2");
	n = ctaphid_feed(&h, NULL, out, 1);
	CHECK(n == 1, "t3c drain step 3");
	n = ctaphid_feed(&h, NULL, out, 1);
	CHECK(n == 0, "t3c drain complete");

	/* ---- t4 CONT out of order -> INVALID_SEQUENCE ---- */
	cid = do_init(&h, out);
	mk_init(cid, CTAPHID_PING, 120, big, 57, pkt);
	ctaphid_feed(&h, pkt, out, 200);
	mk_cont(cid, 1, big + 57, 59, pkt);   /* wrong seq (expect 0) */
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1, "t4 seq error packet");
	CHECK(out[0][4] == (CTAPHID_ERROR | 0x80), "t4 error cmd");
	CHECK(out[0][7] == CTAP1_ERR_INVALID_SEQUENCE, "t4 seq err code");

	/* ---- t5 stray CONT (no message) -> INVALID_SEQUENCE ---- */
	cid = do_init(&h, out);
	mk_cont(cid, 0, big, 10, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1 && out[0][4] == (CTAPHID_ERROR | 0x80) &&
	      out[0][7] == CTAP1_ERR_INVALID_SEQUENCE, "t5 stray CONT error");

	/* ---- t6 oversized BCNT -> INVALID_LENGTH ---- */
	cid = do_init(&h, out);
	mk_init(cid, CTAPHID_CBOR, CTAPHID_MAX_MSG + 1, big, 57, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1 && out[0][7] == CTAP1_ERR_INVALID_LENGTH, "t6 oversized BCNT");

	/* ---- t7 unknown CID -> INVALID_CHANNEL ---- */
	mk_init(cid + 1, CTAPHID_PING, 0, NULL, 0, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1 && out[0][7] == CTAP1_ERR_INVALID_CHANNEL, "t7 unknown cid");

	/* ---- t8 broadcast non-INIT is ignored ---- */
	cid = do_init(&h, out);
	mk_init(0xffffffff, CTAPHID_PING, 0, NULL, 0, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 0, "t8 broadcast non-init ignored");

	/* ---- t9 CBOR with no dispatcher -> INVALID_COMMAND error ---- */
	mk_init(cid, CTAPHID_CBOR, 1, (const uint8_t *)"\x04", 1, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1 && out[0][7] == CTAP1_ERR_INVALID_COMMAND, "t9 no dispatcher");

	/* ---- t10 MSG (CTAP1) unsupported -> INVALID_COMMAND ---- */
	mk_init(cid, CTAPHID_MSG, 1, (const uint8_t *)"\x00", 1, pkt);
	n = ctaphid_feed(&h, pkt, out, 200);
	CHECK(n == 1 && out[0][7] == CTAP1_ERR_INVALID_COMMAND, "t10 CTAP1 MSG refused");

	printf("\nCTAPHID: %d pass, %d fail\n", npass, nfail);
	return nfail ? 1 : 0;
}