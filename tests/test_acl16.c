/* HAL tests: ACL16 APDU framing + dual-SE composite routing with a
 * loopback transport that records writes and plays back canned responses. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../hal/se_transport.h"
#include "../hal/se_acl16.h"
#include "../core/se_driver.h"

/* ---- loopback transport (one response segment per APDU exchange) ---- */
typedef struct { const uint8_t *p; size_t len; } seg_t;
static uint8_t g_written[512];
static size_t g_written_len;
static se_chip g_last_cs;
static seg_t g_segs[8];
static int g_nsegs, g_seg_idx;
static size_t g_seg_pos;
static int g_init_calls;

static int lb_init(void) { g_init_calls++; return SE_T_OK; }
static void lb_cs(se_chip chip, bool active) { if (active) g_last_cs = chip; }
static void lb_reset(se_chip chip) { (void)chip; }
static int lb_write(const uint8_t *buf, size_t len)
{
	/* a new command starts consumption of the next response segment */
	if (g_seg_idx < g_nsegs && g_seg_pos >= g_segs[g_seg_idx].len)
		{ g_seg_idx++; g_seg_pos = 0; }
	if (g_written_len + len > sizeof g_written) return SE_T_ERR_IO;
	memcpy(g_written + g_written_len, buf, len);
	g_written_len += len;
	return SE_T_OK;
}
static int lb_read(uint8_t *buf, size_t len, uint32_t timeout_ms)
{
	(void)timeout_ms;
	if (g_seg_idx >= g_nsegs) return 0;
	seg_t *s = &g_segs[g_seg_idx];
	if (g_seg_pos >= s->len) return 0;   /* this response exhausted => timeout */
	size_t avail = s->len - g_seg_pos;
	size_t take = avail < len ? avail : len;
	memcpy(buf, s->p + g_seg_pos, take);
	g_seg_pos += take;
	return (int)take;
}
static const se_transport_t lb_transport = {
	.init = lb_init, .cs = lb_cs, .reset = lb_reset,
	.write = lb_write, .read = lb_read,
};

/* single-response convenience */
static void lb_reset_state(const uint8_t *playback, size_t plen)
{
	g_written_len = 0;
	g_segs[0].p = playback; g_segs[0].len = plen;
	g_nsegs = 1; g_seg_idx = 0; g_seg_pos = 0;
}
/* multi-response: each APDU consumes the next segment */
static void lb_script(seg_t *segs, int nsegs)
{
	g_written_len = 0;
	for (int i = 0; i < nsegs; i++) g_segs[i] = segs[i];
	g_nsegs = nsegs; g_seg_idx = 0; g_seg_pos = 0;
}

#include "../hal/se_transport.c"
#include "../hal/se_acl16.c"

int main(void)
{
	se_transport_set(&lb_transport);

	/* 1 APDU frame shape: CLA INS P1 P2 Lc data Le */
	se_acl16_t se1;
	se_acl16_init_ctx(&se1, SE_CS_1);
	/* playback: 4 random bytes + 9000 */
	uint8_t pb[] = {0xDE,0xAD,0xBE,0xEF, 0x90,0x00};
	lb_reset_state(pb, sizeof pb);
	uint8_t out[16]; size_t olen = 0;
	int rc = se_acl16_apdu(&se1, 0x80, 0x84, 4, 0, NULL, 0, out, &olen, sizeof out);
	if (rc != 0) { printf("FAIL t1 apdu rc=%d\n", rc); return 1; }
	/* verify frame: 80 84 04 00 00 (no data => Lc omitted, Le=00) */
	const uint8_t want[] = {0x80,0x84,0x04,0x00,0x00};
	if (g_written_len != sizeof want || memcmp(g_written, want, sizeof want) != 0) {
		printf("FAIL t1 frame: "); for(size_t i=0;i<g_written_len;i++)printf("%02x",g_written[i]); printf("\n"); return 1; }
	if (olen != 4 || out[0] != 0xDE) { printf("FAIL t1 resp\n"); return 1; }
	printf("PASS t1 APDU frame shape + response parse\n");

	/* 2 APDU with data: Lc included */
	uint8_t pb2[] = {0x90,0x00};
	lb_reset_state(pb2, sizeof pb2);
	uint8_t seed[32]; memset(seed, 0x11, 32);
	rc = se_acl16_apdu(&se1, 0x80, 0xD0, 0, 0, seed, 32, NULL, 0, 0);
	if (rc != 0) { printf("FAIL t2 rc=%d\n", rc); return 1; }
	/* frame: 80 D0 00 00 20 <32 bytes> 00 */
	if (g_written_len != 5 + 32 + 1 || g_written[4] != 32 || g_written[5] != 0x11) {
		printf("FAIL t2 data frame len=%zu lc=%02x\n", g_written_len, g_written[4]); return 1; }
	printf("PASS t2 APDU with Lc data\n");

	/* 3 status word mapping: 6983 (locked) -> SE_ERR_LOCKED(-3) */
	uint8_t pb3[] = {0x69,0x83};
	lb_reset_state(pb3, sizeof pb3);
	rc = se_acl16_apdu(&se1, 0x80, 0x20, 0, 0, NULL, 0, NULL, 0, 0);
	if (rc != -3) { printf("FAIL t3 sw map rc=%d\n", rc); return 1; }
	printf("PASS t3 status-word to error mapping\n");

	/* 4 get_random chunks large request into <=255 APDUs */
	{
		uint8_t big[300];
		/* two response segments: 255+SW, then 45+SW */
		static uint8_t seg1[257], seg2[47];
		for (int i = 0; i < 255; i++) seg1[i] = (uint8_t)i;
		seg1[255] = 0x90; seg1[256] = 0x00;
		for (int i = 0; i < 45; i++) seg2[i] = (uint8_t)(i + 1);
		seg2[45] = 0x90; seg2[46] = 0x00;
		seg_t segs[2] = { {seg1, sizeof seg1}, {seg2, sizeof seg2} };
		lb_script(segs, 2);
		rc = se_acl16_get_random(&se1, big, sizeof big);
		if (rc != 0) { printf("FAIL t4 rc=%d\n", rc); return 1; }
		printf("PASS t4 get_random chunking\n");
	}

	/* 5 sign_digest frames path + digest correctly */
	{
		uint8_t sigpb[66]; for(int i=0;i<64;i++) sigpb[i]=(uint8_t)(0xA0+i); sigpb[64]=0x90;sigpb[65]=0x00;
		lb_reset_state(sigpb, sizeof sigpb);
		uint32_t path[] = {0x8000002C, 0x80000000, 0x80000000, 0, 0};
		uint8_t digest[32]; memset(digest, 0x22, 32);
		uint8_t sig[64], recid;
		rc = se_acl16_sign_digest(&se1, path, 5, digest, sig, &recid);
		if (rc != 0) { printf("FAIL t5 rc=%d\n", rc); return 1; }
		/* frame: 80 D4 01 00 Lc(1+20+32=53=0x35) [05 path... digest] 00 */
		if (g_written_len < 5 || g_written[4] != 0x35) { printf("FAIL t5 sign frame len\n"); return 1; }
		if (g_written[5] != 5) { printf("FAIL t5 path_len field\n"); return 1; }
		if (sig[0] != 0xA0) { printf("FAIL t5 sig resp\n"); return 1; }
		printf("PASS t5 sign_digest path+digest framing\n");
	}

	/* 6 chip-select routing: SE1 vs SE2 distinct */
	{
		se_acl16_t se2;
		se_acl16_init_ctx(&se2, SE_CS_2);
		lb_reset_state(pb, sizeof pb);
		g_last_cs = SE_CS_2; /* will be overwritten */
		se_acl16_apdu(&se1, 0x80, 0x84, 4, 0, NULL, 0, out, &olen, sizeof out);
		if (g_last_cs != SE_CS_1) { printf("FAIL t6 se1 cs\n"); return 1; }
		lb_reset_state(pb, sizeof pb);
		se_acl16_apdu(&se2, 0x80, 0x84, 4, 0, NULL, 0, out, &olen, sizeof out);
		if (g_last_cs != SE_CS_2) { printf("FAIL t6 se2 cs\n"); return 1; }
		printf("PASS t6 chip-select routing SE1/SE2\n");
	}

	printf("\nALL ACL16 HAL TESTS PASSED\n");
	return 0;
}
