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

	/* status before init -> OK with init=0 */
	rn = hd_link_serve(&se, NULL, HD_CMD_STATUS, 1, NULL, 0, rep, sizeof rep);
	{
		uint8_t z[1] = {0};
		if (check_rep(rep, (size_t)rn, HD_REPLY_OK, z, 1, "status-before-init")) return 1;
	}

	/* ping */
	s_init = 1;
	rn = hd_link_serve(&se, NULL, HD_CMD_PING, 2, NULL, 0, rep, sizeof rep);
	{
		uint8_t P = 0x50;
		if (check_rep(rep, (size_t)rn, HD_REPLY_OK, &P, 1, "ping")) return 1;
	}

	/* init now; status says 1 */
	s_init = 1;
	rn = hd_link_serve(&se, NULL, HD_CMD_STATUS, 3, NULL, 0, rep, sizeof rep);
	{
		uint8_t o = 1;
		if (check_rep(rep, (size_t)rn, HD_REPLY_OK, &o, 1, "status-after-init")) return 1;
	}

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