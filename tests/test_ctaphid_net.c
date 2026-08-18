/* End-to-end CTAPHID transport test (design doc 09 §7 / F3 exit criteria).
 *
 * Drives the FULL stack exactly as the USB HID transport will on hardware:
 *   host packets -> fido_ctaphid framing (INIT + CONT) -> real ctap2
 *   dispatcher -> fido_core -> mock SE -> response frames back out.
 * This is the host-verifiable core of the F3 "CTAPHID 帧层上板" milestone;
 * the only thing this test does NOT exercise is the TinyUSB descriptor /
 * report callback layer itself (hardware-bound, see usb F3).
 *
 * Protocol flow mirrors a WebAuthn client (python-fido2 / browser):
 *   1. INIT on broadcast    -> gets a fresh channel CID
 *   2. GetInfo (CBOR)       -> capabilities, options, rk:false
 *   3. makeCredential       -> attestationObject {fmt:"none", authData}
 *   4. getAssertion         -> {credential, authData, signature}
 * plus transport-level error paths through the real dispatcher.
 */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include "../core/fido_ctaphid.h"
#include "../core/ctap2.h"
#include "../core/fido_core.h"
#include "../core/se_driver.h"

#include "../core/sha512.c"
#include "../core/hkdf.c"
#include "../core/secp256r1.c"
#include "../core/rfc6979.c"
#include "../core/cbor.c"
#include "../core/fido_core.c"
#include "../core/ctap2.c"
#include "../core/fido_ctaphid.c"
#include "../core/se_mock.c"

static int npass, nfail;
#define CHECK(cond, name) do { \
	if (cond) { npass++; printf("PASS %s\n", name); } \
	else { nfail++; printf("FAIL %s\n", name); } \
} while (0)

static int confirm_yes(const char *rp, bool is_reg)
{
	(void)rp; (void)is_reg;
	return 1;
}

/* ---- HID packet builders (the host side) ---- */

static void mk_init_pkt(uint32_t cid, uint8_t cmd, const uint8_t *data,
                        uint16_t dlen, uint16_t bcnt, uint8_t p[64])
{
	memset(p, 0, 64);
	p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
	p[4] = cmd | 0x80;
	p[5] = bcnt >> 8; p[6] = bcnt;
	if (dlen > 57) dlen = 57;
	if (dlen) memcpy(p + 7, data, dlen);
}

static void mk_cont_pkt(uint32_t cid, uint8_t seq, const uint8_t *data,
                        uint16_t dlen, uint8_t p[64])
{
	memset(p, 0, 64);
	p[0] = cid >> 24; p[1] = cid >> 16; p[2] = cid >> 8; p[3] = cid;
	p[4] = seq & 0x7f;
	if (dlen > 59) dlen = 59;
	if (dlen) memcpy(p + 5, data, dlen);
}

/* Send a full CTAPHID message: first INIT packet, then CONTs. Runs the feed
 * loop, capturing reply packets emitted from EVERY feed call (the dispatch
 * fires on the final input packet, so replies can appear mid-sequence).
 * Reassembles the response message from its INIT frame BCNT + payload.
 * Copies status+payload into resp; *resp_len gets payload length.
 * Returns the status byte. */
static int send_msg(ctaphid_t *h, uint32_t cid, uint8_t cmd,
                    const uint8_t *data, uint16_t dlen,
                    uint8_t *resp, size_t resp_cap, size_t *resp_len,
                    uint8_t (*out)[64], int max_out)
{
	uint8_t pkt[64];
	uint8_t rbuf[CTAPHID_MAX_MSG + 8];
	size_t rlen = 0;
	size_t bcnt = 0;
	bool got_first = false;
	int feed_guard = 0;

	/* helper: accumulate whatever packets a feed call emitted */
	#define ACCUM(k, tag) do { \
		(void)tag; \
		for (int i = 0; i < (k); i++) { \
			uint8_t *f = out[i]; \
			if (!got_first) { \
				bcnt = ((uint16_t)f[5] << 8) | f[6]; \
				got_first = true; \
				if (bcnt > sizeof rbuf) bcnt = sizeof rbuf; \
				if (bcnt == 0) continue; \
				size_t room = bcnt < 57 ? bcnt : 57; \
				memcpy(rbuf, f + 7, room); \
				rlen = room; \
			} else { \
				if (rlen < bcnt) { \
					size_t room = bcnt - rlen; \
					if (room > 59) room = 59; \
					memcpy(rbuf + rlen, f + 5, room); \
					rlen += room; \
				} \
			} \
		} \
	} while (0)

	/* first packet holds up to 57 bytes and carries BCNT */
	uint16_t first = dlen < 57 ? dlen : 57;
	mk_init_pkt(cid, cmd, data, first, dlen, pkt);
	if (++feed_guard > 1024) return CTAP1_ERR_OTHER;
	int nk = ctaphid_feed(h, pkt, out, max_out);
	ACCUM(nk, "init");
	uint16_t off = first;
	uint8_t seq = 0;
	while (off < dlen) {
		uint16_t take = dlen - off;
		if (take > 59) take = 59;
		mk_cont_pkt(cid, seq, data + off, take, pkt);
		if (++feed_guard > 1024) return CTAP1_ERR_OTHER;
		nk = ctaphid_feed(h, pkt, out, max_out);
		ACCUM(nk, "cont");
		off += take;
		seq++;
	}
	/* drain any remaining staged response (multi-msg pipelines) */
	for (;;) {
		if (++feed_guard > 1024) break;
		int k = ctaphid_feed(h, NULL, out, max_out);
		if (k == 0) break;
		ACCUM(k, "drain");
	}
	#undef ACCUM

	if (!got_first || bcnt == 0) {
		*resp_len = 0;
		if (resp_cap > 0) resp[0] = CTAP1_ERR_OTHER;
		return CTAP1_ERR_OTHER;
	}
	if (bcnt > resp_cap)
		bcnt = resp_cap;
	memcpy(resp, rbuf, bcnt);
	*resp_len = bcnt > 0 ? bcnt - 1 : 0;
	return bcnt > 0 ? rbuf[0] : 0xff;
}

/* Build the makeCredential CBOR payload used in test_fido.c. */
static size_t build_makecred(uint8_t *msg, size_t cap)
{
	cbor_writer_t w;
	cbor_writer_init(&w, msg, cap);
	uint8_t cdh[32]; memset(cdh, 0xAB, 32);
	cbor_write_map_head(&w, 4);
	/* 1: clientDataHash */
	cbor_write_uint(&w, 1);
	cbor_write_bytes(&w, cdh, 32);
	/* 2: rp */
	cbor_write_uint(&w, 2);
	cbor_write_map_head(&w, 2);
	cbor_write_uint(&w, 1); cbor_write_text(&w, "example.com");
	cbor_write_uint(&w, 2); cbor_write_text(&w, "Example");
	/* 3: user */
	cbor_write_uint(&w, 3);
	cbor_write_map_head(&w, 3);
	cbor_write_uint(&w, 1); cbor_write_bytes(&w, cdh, 8);
	cbor_write_uint(&w, 2); cbor_write_text(&w, "bob");
	cbor_write_uint(&w, 3); cbor_write_text(&w, "Bob");
	/* 4: pubKeyCredParams -> [{alg:-7,type:"public-key"}] */
	cbor_write_uint(&w, 4);
	cbor_write_array_head(&w, 1);
	cbor_write_map_head(&w, 2);
	cbor_write_uint(&w, 3); cbor_write_int(&w, -7);
	cbor_write_uint(&w, 1); cbor_write_text(&w, "public-key");
	return w.len;
}

static size_t build_getassert(const uint8_t *credid, size_t credid_len,
                              uint8_t *msg, size_t cap)
{
	cbor_writer_t w;
	cbor_writer_init(&w, msg, cap);
	uint8_t cdh[32]; memset(cdh, 0xCD, 32);
	cbor_write_map_head(&w, 3);
	/* 1: rpId */
	cbor_write_uint(&w, 1);
	cbor_write_text(&w, "example.com");
	/* 2: clientDataHash */
	cbor_write_uint(&w, 2);
	cbor_write_bytes(&w, cdh, 32);
	/* 3: allowList -> [{1:id, 2:"public-key"}] */
	cbor_write_uint(&w, 3);
	cbor_write_array_head(&w, 1);
	cbor_write_map_head(&w, 2);
	cbor_write_uint(&w, 1); cbor_write_bytes(&w, credid, credid_len);
	cbor_write_uint(&w, 2); cbor_write_text(&w, "public-key");
	return w.len;
}

int main(void)
{
	/* host-side SE init (device boot). */
	se_mock_reset();
	const se_driver_t *se = se_active();
	uint8_t seed[64]; memset(seed, 0x11, 64);
	se->store_seed(seed);
	uint8_t pin[4] = {'1','2','3','4'};
	se_mock_set_pin(pin, 4);
	se->verify_pin(pin, 4, NULL, NULL);
	fido_set_confirm_handler(confirm_yes);

	ctaphid_t h;
	ctaphid_init(&h);
	h.dispatch = ctap2_handle;

	uint8_t pkt[64];
	uint8_t out[16][64];
	uint8_t resp[CTAPHID_MAX_MSG];
	size_t rlen;

	/* ---- t1 INIT on broadcast: fresh CID + capabilities ---- */
	uint8_t nonce[8] = {1,2,3,4,5,6,7,8};
	mk_init_pkt(0xffffffff, CTAPHID_INIT, nonce, 8, 8, pkt);
	int n = ctaphid_feed(&h, pkt, out, 16);
	CHECK(n == 1 && (out[0][4] == (CTAPHID_INIT | 0x80)),
	      "t1 INIT acknowledged");
	CHECK(memcmp(out[0] + 7, nonce, 8) == 0, "t1 nonce echoed");
	uint32_t cid = ((uint32_t)out[0][15] << 24) | ((uint32_t)out[0][16] << 16) |
	               ((uint32_t)out[0][17] << 8) | out[0][18];
	CHECK(cid != 0 && cid != 0xffffffff, "t1 cid allocated");
	CHECK(out[0][23] == (CTAPHID_CAP_WINK | CTAPHID_CAP_CBOR | CTAPHID_CAP_NMSG), "t1 caps CBOR+NMSG+WINK");

	/* ---- t2 GetInfo via the wire ---- */
	{
		uint8_t ginfo[2] = {CTAP2_CMD_GET_INFO, 0xa0};
		int st = send_msg(&h, cid, CTAPHID_CBOR, ginfo, 2,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_OK, "t2 GetInfo status 0");
		CHECK(rlen > 20, "t2 GetInfo payload non-trivial");
		/* payload starts with CBOR map head (0xa5.. ) */
		CHECK(resp[1] >= 0xa0 && resp[1] <= 0xb7, "t2 GetInfo CBOR map");
	}

	/* ---- t3 makeCredential: multi-packet request -> attestation ---- */
	uint8_t mc[256];
	size_t mc_len = build_makecred(mc, sizeof mc);
	CHECK(mc_len > 57, "t3 request spans multiple packets");
	{
		uint8_t wire[260];
		wire[0] = CTAP2_CMD_MAKE_CREDENTIAL;
		memcpy(wire + 1, mc, mc_len);
		int st = send_msg(&h, cid, CTAPHID_CBOR, wire, mc_len + 1,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_OK, "t3 makeCredential status 0");
		CHECK(rlen > 0, "t3 attestation payload present");
		CHECK(resp[1] == 0xa3, "t3 attestation object map head");
		CHECK(resp[2] == 0x01 && resp[3] == 0x64 &&
		      memcmp(resp + 4, "none", 4) == 0, "t3 fmt none");
	}

	/* ---- t4 getAssertion: RP-known credid from register response ---- */
	uint8_t credid[FIDO_CREDID_LEN];
	{
		uint8_t wire[260];
		wire[0] = CTAP2_CMD_MAKE_CREDENTIAL;
		memcpy(wire + 1, mc, mc_len);
		int st = send_msg(&h, cid, CTAPHID_CBOR, wire, mc_len + 1,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_OK, "t4 second registration ok");
		/* parse attestationObject {fmt, authData, attStmt} */
		cbor_reader_t rd;
		cbor_reader_init(&rd, resp + 1, rlen, 64);
		size_t pairs;
		cbor_read_map_head(&rd, &pairs);
		const uint8_t *authdata = NULL;
		size_t ad_len = 0;
		for (size_t i = 0; i < pairs; i++) {
			uint64_t k;
			cbor_read_uint(&rd, &k);
			if (k == 2) {
				cbor_read_bytes_head(&rd, &authdata, &ad_len);
			} else {
				cbor_skip(&rd);
			}
		}
		CHECK(authdata != NULL && ad_len >= 37 + 67, "t4 authData parsed");
		/* authData: rpIdHash(32) flags(1) signCount(4) aaguid(16)
		 * credIdLen(2) credId(21) coseKey... */
		uint8_t flags = authdata[32];
		CHECK(flags & FIDO_AT_FLAG_AT, "t4 AT flag set");
		CHECK(flags & FIDO_AT_FLAG_UP, "t4 UP flag set");
		uint16_t idlen = (uint16_t)((authdata[37 + 16] << 8) |
		                            authdata[37 + 16 + 1]);
		CHECK(idlen == FIDO_CREDID_LEN, "t4 credId len 21");
		memcpy(credid, authdata + 37 + 16 + 2, idlen);
		printf("PASS t4c credid extracted (len %u)\n", idlen);
	}

	/* ---- t5 getAssertion over the wire + signature present ---- */
	{
		uint8_t ga[300];
		size_t ga_len = build_getassert(credid, sizeof credid, ga, sizeof ga);
		uint8_t wire[304];
		wire[0] = CTAP2_CMD_GET_ASSERTION;
		memcpy(wire + 1, ga, ga_len);
		int st = send_msg(&h, cid, CTAPHID_CBOR, wire, ga_len + 1,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_OK, "t5 getAssertion status 0");
		CHECK(resp[1] == 0xa3, "t5 assertion map head");
		/* signature: {3: bstr(DER-encoded ECDSA)}. WebAuthn §6.5.5 requires
		 * ES256 assertions to be DER (ASN.1) encoded, so the value is a
		 * variable-length 64..72-byte byte string whose first byte is 0x30
		 * (SEQUENCE), not a fixed 64-byte raw r||s. */
		uint8_t *sig = memmem(resp, rlen + 1, (void*)"\x03\x58", 2);
		CHECK(sig != NULL, "t5 signature member (key 3) present");
		if (sig != NULL) {
			size_t off = (size_t)(sig - resp);
			uint8_t dlen = resp[off + 2];
			int ok = off + 3 + dlen <= rlen + 1 &&
			         dlen >= 64 && dlen <= 72 &&
			         resp[off + 3] == 0x30;
			CHECK(ok, "t5 DER-encoded 64-72 byte signature");
		}
	}

	/* ---- t6 denied confirm blocks signing at the wire level ---- */
	fido_set_confirm_handler(NULL);
	{
		uint8_t ga[300];
		size_t ga_len = build_getassert(credid, sizeof credid, ga, sizeof ga);
		uint8_t wire[304];
		wire[0] = CTAP2_CMD_GET_ASSERTION;
		memcpy(wire + 1, ga, ga_len);
		int st = send_msg(&h, cid, CTAPHID_CBOR, wire, ga_len + 1,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_ERR_OPERATION_DENIED, "t6 denied over wire");
	}

	/* ---- t7 framing error crosses the wire as CTAPHID_ERROR ---- */
	{
		/* stray CONT addressed to our channel (no message in flight) */
		mk_cont_pkt(cid, 0, (const uint8_t*)"xxxx", 4, pkt);
		n = ctaphid_feed(&h, pkt, out, 16);
		CHECK(n == 1 && out[0][4] == (CTAPHID_ERROR | 0x80),
		      "t7 framing error -> CTAPHID_ERROR");
		CHECK(out[0][7] == CTAP1_ERR_INVALID_SEQUENCE,
		      "t7 invalid sequence code");
	}

	/* ---- t8 unknown channel gets INVALID_CHANNEL ---- */
	{
		uint8_t ginfo[2] = {CTAP2_CMD_GET_INFO, 0xa0};
		mk_init_pkt(0x12345678, CTAPHID_CBOR, ginfo, 2, 2, pkt);
		n = ctaphid_feed(&h, pkt, out, 16);
		CHECK(n == 1 && out[0][7] == CTAP1_ERR_INVALID_CHANNEL,
		      "t8 unknown cid rejected");
	}

	/* ---- t9 blink (WINK) is answered, CBOR keeps working after ---- */
	{
		mk_init_pkt(cid, CTAPHID_WINK, NULL, 0, 0, pkt);
		n = ctaphid_feed(&h, pkt, out, 16);
		CHECK(n == 1 && out[0][4] == (CTAPHID_WINK | 0x80),
		      "t9 wink acked");
		/* channel still live for CBOR */
		uint8_t ginfo[2] = {CTAP2_CMD_GET_INFO, 0xa0};
		int st = send_msg(&h, cid, CTAPHID_CBOR, ginfo, 2,
		                  resp, sizeof resp, &rlen, out, 16);
		CHECK(st == CTAP2_OK, "t9 GetInfo after wink");
	}

	printf("\nCTAPHID-NET: %d pass, %d fail\n", npass, nfail);
	return nfail ? 1 : 0;
}