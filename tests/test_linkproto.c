/* Host-side test of linkproto framing: encode, corrupt, decode. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/linkproto.c"

int main(void)
{
	uint8_t digest[32];
	memset(digest, 0xAB, sizeof digest);
	uint8_t frm[HD_LINK_MAX_FRAME];
	int n = hd_link_frame_cmd(HD_CMD_SIGN, 7, digest, sizeof digest, frm, sizeof frm);
	if (n <= 0) { printf("FAIL frame n=%d\n", n); return 1; }

	uint8_t type; uint16_t seq; const uint8_t *pl; size_t plen;
	if (hd_link_parse(frm, (size_t)n, &type, &seq, &pl, &plen) != 0) {
		printf("FAIL parse\n"); return 1;
	}
	if (type != HD_CMD_SIGN || seq != 7 || plen != 32 || memcmp(pl, digest, 32)) {
		printf("FAIL roundtrip type=%u seq=%u plen=%zu\n", type, seq, plen); return 1;
	}
	printf("cmd roundtrip OK (type=%u seq=%u plen=%zu)\n", type, seq, plen);

	/* corrupt one payload byte -> must be rejected */
	frm[n - 3] ^= 0xFF;
	if (hd_link_parse(frm, (size_t)n, &type, &seq, &pl, &plen) == 0) {
		printf("FAIL: corrupt frame accepted\n"); return 1;
	}
	printf("corrupt frame rejected OK\n");

	/* reply encode */
	memset(frm, 0, sizeof frm);
	int rn = hd_link_frame_reply(HD_REPLY_OK, 7, 0, digest, 32, frm, sizeof frm);
	if (rn <= 0 || hd_link_parse(frm, (size_t)rn, &type, &seq, &pl, &plen) != 0) {
		printf("FAIL reply\n"); return 1;
	}
	printf("reply roundtrip OK\n");
	return 0;
}