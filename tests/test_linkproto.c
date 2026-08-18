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

	/* round-29 regression: the largest SIGN reply (4-byte sig_count +
	 * OS_PSBT_MAX_INPUTS×65) must frame — the old staging buffer
	 * (4+512) rejected replies for ≥8-input BTC PSBTs. */
	{
		uint8_t big[4 + 16 * 65];   /* 4 + OS_PSBT_MAX_INPUTS×65 = 1044 */
		memset(big, 0x5A, sizeof big);
		memset(frm, 0, sizeof frm);
		int bn = hd_link_frame_reply(HD_REPLY_OK, 9, 0, big, sizeof big,
		                             frm, sizeof frm);
		if (bn <= 0) { printf("FAIL big reply framing (16-input PSBT)\n"); return 1; }
		/* reply payload = rc(4 BE) || original payload */
		if (hd_link_parse(frm, (size_t)bn, &type, &seq, &pl, &plen) != 0 ||
		    plen != 4 + sizeof big || pl[0] != 0 || pl[1] != 0 ||
		    pl[2] != 0 || pl[3] != 0 ||
		    memcmp(pl + 4, big, sizeof big) != 0) {
			printf("FAIL big reply roundtrip\n"); return 1;
		}
		printf("big reply (1044B payload) roundtrip OK\n");
	}
	return 0;
}