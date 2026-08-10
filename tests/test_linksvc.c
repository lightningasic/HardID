/* Host-side test of the link service using a tiny fake SE. */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "../core/linkproto.c"
#include "../core/linksvc.c"

static int s_init = 0;
static int s_rc = 0;
static bool s_confirm_result = true;

static bool lv_is_init(void){ return s_init != 0; }
static int	lv_unlock(const uint8_t *p, size_t n){ (void)p; (void)n; return s_rc; }
static int	lv_sign(const uint8_t *d, uint8_t *sig)
{
	if (!s_init) return -5;
	for (int i = 0; i < 64; i++) sig[i] = (uint8_t)(d[i % 32] ^ (uint8_t)i);
	return s_rc;
}

static hd_link_se_t se = { lv_is_init, lv_unlock, lv_sign };

static bool ui_confirm(const uint8_t *d){ (void)d; return s_confirm_result; }

static int reply_type(const uint8_t *buf, size_t len)
{
	uint8_t t; uint16_t seq; hd_link_parse(buf, len, &t, &seq, NULL, NULL);
	(void)seq; return t;
}

static int check_rep(const uint8_t *rep, size_t rn, int want_type,
                     const uint8_t *want, size_t wlen, const char *label)
{
	uint8_t t; uint16_t seq; const uint8_t *pl; size_t plen;
	if (rn <= 0) { printf("FAIL rn=%d %s\n", (int)rn, label); return 1; }
	if (hd_link_parse(rep, rn, &t, &seq, &pl, &plen) != 0) {
		printf("FAIL parse %s\n", label); return 1; }
	if (t != want_type) { printf("FAIL type %u want %u %s\n", t, want_type, label); return 1; }
	/* payload begins with a 4-byte rc prefix, then the data */
	pl += 4; plen -= 4;
	if (plen != wlen || (want && memcmp(pl, want, wlen))) {
		printf("FAIL payload %s plen=%zu want=%zu\n", label, plen, wlen); return 1; }
	printf("ok %s (type=%u plen=%zu)\n", label, t, plen);
	return 0;
}

int main(void)
{
	uint8_t rep[HD_LINK_MAX_FRAME]; int rn;
	uint8_t digest[32]; memset(digest, 0x11, 32);

	s_rc = 0; s_init = 0; s_confirm_result = true;

	/* Single-verb contract (PRD §3.4): every non-SIGN verb is rejected —
	 * old PING/STATUS, reserved codes, and unknown bytes alike. This is
	 * the "非 SIGN 动词 100% 拒绝" acceptance check. */
	{
		const uint8_t verbs[] = { 0x00, 0x01, 0x02, 0x04, 0x05, 0x7F, 0x80, 0xFE, 0xFF };
		for (size_t i = 0; i < sizeof verbs; i++) {
			rn = hd_link_serve(&se, NULL, verbs[i], (uint16_t)(10u + i), NULL, 0,
			                   rep, sizeof rep);
			if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) {
				printf("FAIL non-SIGN verb 0x%02x was not rejected\n", verbs[i]);
				return 1;
			}
		}
		printf("ok non-SIGN verbs rejected (fuzz 0x%02x..0x%02x)\n",
		       verbs[0], verbs[sizeof verbs - 1]);
	}

	/* non-SIGN verbs are rejected even after init */
	s_init = 1;
	rn = hd_link_serve(&se, NULL, 0x02, 20, NULL, 0, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL post-init reject\n"); return 1; }
	printf("ok non-SIGN rejected post-init\n");

	/* sign with valid digest, confirm true -> OK 64B */
	rn = hd_link_serve(&se, ui_confirm, HD_CMD_SIGN, 4, digest, 32, rep, sizeof rep);
	if (check_rep(rep, (size_t)rn, HD_REPLY_OK, NULL, 64, "sign-confirmed")) return 1;

	/* sign with confirm=false -> err/auth */
	s_confirm_result = false;
	rn = hd_link_serve(&se, ui_confirm, HD_CMD_SIGN, 5, digest, 32, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL declined\n"); return 1; }
	printf("ok sign-declined -> err\n");

	/* sign with bad digest length -> err param */
	s_confirm_result = true;
	rn = hd_link_serve(&se, ui_confirm, HD_CMD_SIGN, 6, digest, 16, rep, sizeof rep);
	if (reply_type(rep, (size_t)rn) != HD_REPLY_ERR) { printf("FAIL badlen\n"); return 1; }
	printf("ok sign-badlen -> err\n");

	printf("ALL PASS\n");
	return 0;
}