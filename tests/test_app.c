/* App registry + sign delegation tests (V2.0). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/se_driver.h"

#include "../core/se_mock.c"
#include "../core/app_registry.c"
#include "../core/app_catalog.c"
#include "../core/signsvc.c"
#include "../core/keccak.c"
#include "../core/clearsign.c"
#include "../core/psbt.c"
#include "../core/hkdf.c"
#include "../core/base58.c"

/* ---- RLP helpers (same as test_clearsign) ---- */
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

/* ---- UI confirm hook ---- */
static int s_confirms;          /* how many times confirm was called */
static int s_confirm_answer;    /* true to accept */
static bool confirm_ui(const os_tx_intent *it)
{
	(void)it;
	s_confirms++;
	return s_confirm_answer;
}

int main(void)
{
	const se_driver_t *se = se_active();
	se_mock_reset();

	/* 1 core apps present: BTC + ETH */
	if (os_app_count() != 2) { printf("FAIL t1 count=%zu\n", os_app_count()); return 1; }
	const os_app *btc = os_app_by_id("btc");
	const os_app *eth = os_app_by_id("eth");
	if (!btc || !eth) { printf("FAIL t1 lookup\n"); return 1; }
	if (btc->coin_type != 0 || eth->coin_type != 60) { printf("FAIL t1 coin\n"); return 1; }
	printf("PASS t1 core apps registered\n");

	/* 2 install/remove third-party app */
	os_app usdt = {
		.app_id = "usdt", .name = "Tether", .coin_type = 1, .version = 1,
		.state = OS_APP_INSTALLED, .parse = eth->parse,
	};
	if (os_app_register(&usdt) != 0) { printf("FAIL t2 register\n"); return 1; }
	if (os_app_count() != 3) { printf("FAIL t2 count\n"); return 1; }
	const os_app *u = os_app_by_id("usdt");
	if (!u || u->state != OS_APP_INSTALLED) { printf("FAIL t2 lookup\n"); return 1; }
	if (os_app_uninstall("usdt") != 0) { printf("FAIL t2 uninstall\n"); return 1; }
	if (os_app_count() != 2) { printf("FAIL t2 post-uninstall\n"); return 1; }
	printf("PASS t2 install/uninstall\n");

	/* 3 duplicate app_id / coin_type rejected */
	if (os_app_register(&usdt) != 0) { printf("FAIL t3a register usdt\n"); return 1; }
	os_app dup = { .app_id = "usdt2", .name = "Dup", .coin_type = 1, .version = 1,
	               .parse = eth->parse };
	if (os_app_register(&dup) != -1) { printf("FAIL t3b dup coin rejected\n"); return 1; }
	os_app dupe = { .app_id = "usdt", .name = "Dup", .coin_type = 7, .version = 1,
	                .parse = eth->parse };
	if (os_app_register(&dupe) != -1) { printf("FAIL t3c dup id rejected\n"); return 1; }
	printf("PASS t3 duplicate rejection\n");

	/* 4 anti-rollback version bump */
	if (os_app_bump_version("usdt", 5) != 0) { printf("FAIL t4a bump\n"); return 1; }
	if (os_app_bump_version("usdt", 3) != -1) { printf("FAIL t4b downgrade\n"); return 1; }
	printf("PASS t4 anti-rollback\n");

	/* 5 suspend disables signing */
	if (os_app_suspend("usdt") != 0) { printf("FAIL t5a suspend\n"); return 1; }
	if (os_app_by_id("usdt") != NULL) { printf("FAIL t5b suspended not visible\n"); return 1; }
	printf("PASS t5 suspend\n");

	/* 6 sign delegation over EVM tx */
	/* provision seed + pin, unlock session */
	uint8_t seed[64]; memset(seed, 0x11, 64);
	if (se->store_seed(seed) != SE_OK) { printf("FAIL t6 store\n"); return 1; }
	uint8_t pin[4] = { '1', '2', '3', '4' };
	if (se->set_pin(pin, 4) != SE_OK) { printf("FAIL t6 setpin\n"); return 1; }
	if (se->verify_pin(pin, 4, NULL, NULL) != SE_OK) { printf("FAIL t6 unlock\n"); return 1; }

	uint8_t tx[2048]; uint8_t to[20];
	for (int i = 0; i < 20; i++) to[i] = 0x10 + i;
	size_t n = build_legacy(tx, 20, 21000, to, 1000, NULL, 0);

	uint32_t path[3] = { 0x80000000u | 44, 0x80000000u | 60,
	                     0x80000000u | 0 };        /* m/44'/60'/0' */

	/* wrong path (BTC coin branch) must be refused */
	s_confirm_answer = 1; s_confirms = 0;
	uint32_t bad_path[3] = { 0x80000000u | 44, 0x80000000u | 0,
	                         0x80000000u | 0 };
	os_sign_outcome o = os_signsvc_delegate("eth", tx, n, bad_path, 3, confirm_ui);
	if (o.result != OS_SIGN_PARSE_ERR) { printf("FAIL t6a wrong-path rc=%d\n", o.result); return 1; }

	/* suspended app must be refused */
	os_app usdt2 = { .app_id = "xrp", .name = "XRP", .coin_type = 144, .version = 1,
	                 .parse = eth->parse };
	os_app_register(&usdt2);
	os_app_suspend("xrp");
	o = os_signsvc_delegate("xrp", tx, n, path, 3, confirm_ui);
	if (o.result != OS_SIGN_DISABLED) { printf("FAIL t6b suspended rc=%d\n", o.result); return 1; }

	/* good path, user confirms -> signed, signature present */
	s_confirm_answer = 1; s_confirms = 0;
	o = os_signsvc_delegate("eth", tx, n, path, 3, confirm_ui);
	if (o.result != OS_SIGN_OK) { printf("FAIL t6c sign rc=%d\n", o.result); return 1; }
	if (s_confirms != 1) { printf("FAIL t6d confirms=%d\n", s_confirms); return 1; }
	uint8_t nonzero = 0;
	for (int i = 0; i < 64; i++) nonzero |= o.sig64[i];
	if (nonzero == 0) { printf("FAIL t6e empty sig\n"); return 1; }
	printf("PASS t6 sign delegation\n");

	/* 7 user reject -> rejected, no signature */
	s_confirm_answer = 0; s_confirms = 0;
	o = os_signsvc_delegate("eth", tx, n, path, 3, confirm_ui);
	if (o.result != OS_SIGN_REJECTED) { printf("FAIL t7 reject rc=%d\n", o.result); return 1; }
	printf("PASS t7 user rejection\n");

	/* 8 malformed tx -> parse error */
	uint8_t junk[8] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	o = os_signsvc_delegate("eth", junk, sizeof(junk), path, 3, confirm_ui);
	if (o.result != OS_SIGN_PARSE_ERR) { printf("FAIL t8 junk rc=%d\n", o.result); return 1; }
	printf("PASS t8 malformed tx\n");

	/* 9 intent verification standalone */
	os_tx_intent it;
	if (os_clearsign_parse_evm(tx, n, &it) != 0) { printf("FAIL t9 parse\n"); return 1; }
	if (!os_signsvc_verify_intent("eth", tx, n, &it)) { printf("FAIL t9 verify ok\n"); return 1; }
	it.amount = 99999; /* tamper */
	if (os_signsvc_verify_intent("eth", tx, n, &it)) { printf("FAIL t9 verify tamper\n"); return 1; }
	printf("PASS t9 intent verification\n");

	/* 10 UNKNOWN-intent data_hash must be verified (anti-spoof) */
	/* Build a tx with garbage calldata → UNKNOWN with data_hash set. */
	uint8_t call[4] = { 0xab, 0xcd, 0xef, 0x01 };
	uint8_t txu[2048];
	size_t nu = build_legacy(txu, 20, 21000, to, 0, call, 4);
	os_tx_intent iu;
	if (os_clearsign_parse_evm(txu, nu, &iu) != 0) { printf("FAIL t10 parse\n"); return 1; }
	if (iu.kind != OS_INTENT_UNKNOWN) { printf("FAIL t10 kind=%d\n", iu.kind); return 1; }
	if (!os_signsvc_verify_intent("eth", txu, nu, &iu)) { printf("FAIL t10 verify ok\n"); return 1; }
	iu.data_hash[0] ^= 0xff; /* tamper hash */
	if (os_signsvc_verify_intent("eth", txu, nu, &iu)) { printf("FAIL t10 verify data_hash\n"); return 1; }
	printf("PASS t10 unknown data_hash check\n");

	/* 11 suspended app cannot be re-registered under same id; a SUSPENDED
	 * app's coin_type is also still reserved (M7). Use a distinct coin. */
	os_app xrpp = { .app_id = "xrpl", .name = "XRPL", .coin_type = 501, .version = 1,
	                .parse = eth->parse };
	if (os_app_register(&xrpp) != 0) { printf("FAIL t11a register\n"); return 1; }
	if (os_app_suspend("xrpl") != 0) { printf("FAIL t11b suspend\n"); return 1; }
	/* suspended coin 501 must not be re-claimable by a different id */
	os_app grab = { .app_id = "grabber", .name = "Grab", .coin_type = 501, .version = 1,
	                .parse = eth->parse };
	if (os_app_register(&grab) != -1) { printf("FAIL t11c suspended coin claimed\n"); return 1; }
	/* same id also still blocked while suspended */
	os_app xrpp2 = { .app_id = "xrpl", .name = "XRPL2", .coin_type = 502, .version = 1,
	                 .parse = eth->parse };
	if (os_app_register(&xrpp2) != -1) { printf("FAIL t11d re-register suspended\n"); return 1; }
	/* uninstall first then re-register is allowed */
	if (os_app_uninstall("xrpl") != 0) { printf("FAIL t11e uninstall\n"); return 1; }
	if (os_app_register(&xrpp2) != 0) { printf("FAIL t11f re-register after uninstall\n"); return 1; }
	printf("PASS t11 suspended id+coin guard\n");

	os_app_uninstall("usdt");
	os_app_uninstall("xrpl2");

	/* 12 shared core demo-tx builder parity: the tx the on-device demo
	 * signs must parse to the same intent the RLP test harness builds. */
	uint8_t dt[64]; uint8_t to11[20]; memset(to11, 0x11, sizeof to11);
	size_t dlen = os_clearsign_build_demo_legacy(dt, 20, 21000, to11, 1000);
	if (dlen == 0) { printf("FAIL t12 builder\n"); return 1; }
	os_tx_intent di;
	if (os_clearsign_parse_evm(dt, dlen, &di) != 0) { printf("FAIL t12 parse\n"); return 1; }
	if (di.kind != OS_INTENT_TRANSFER || di.amount != 1000 ||
	    di.fee_limit != 21000ULL * 20ULL) {
		printf("FAIL t12 intent kind=%d amt=%llu fee=%llu\n",
		       di.kind, (unsigned long long)di.amount,
		       (unsigned long long)di.fee_limit); return 1;
	}
	if (!os_signsvc_verify_intent("eth", dt, dlen, &di)) { printf("FAIL t12 verify\n"); return 1; }
	printf("PASS t12 demo-tx parity\n");

	/* 13 M6: an app_id colliding with a CORE app id must be rejected,
	 * even with a free coin_type. */
	os_app fake = { .app_id = "btc", .name = "FakeBTC", .coin_type = 999, .version = 1,
	                .parse = eth->parse };
	if (os_app_register(&fake) != -1) { printf("FAIL t13 core-id collision allowed\n"); return 1; }
	os_app fake2 = { .app_id = "eth", .name = "FakeETH", .coin_type = 998, .version = 1,
	                 .parse = eth->parse };
	if (os_app_register(&fake2) != -1) { printf("FAIL t13b core-id collision allowed\n"); return 1; }
	printf("PASS t13 core app_id collision rejected\n");

	/* 14 M9: unterminated app_id/name buffers must be rejected (strcmp
	 * would otherwise read out of bounds). */
	os_app notnul; memset(&notnul, 0, sizeof notnul);
	memset(notnul.app_id, 'x', sizeof notnul.app_id); /* no NUL in 16 bytes */
	snprintf(notnul.name, sizeof notnul.name, "NN");
	notnul.coin_type = 997; notnul.version = 1; notnul.parse = eth->parse;
	if (os_app_register(&notnul) != -1) { printf("FAIL t14 unterminated id allowed\n"); return 1; }
	os_app notnul2; memset(&notnul2, 0, sizeof notnul2);
	snprintf(notnul2.app_id, sizeof notnul2.app_id, "okid");
	memset(notnul2.name, 'y', sizeof notnul2.name); /* no NUL in 24 bytes */
	notnul2.coin_type = 996; notnul2.version = 1; notnul2.parse = eth->parse;
	if (os_app_register(&notnul2) != -1) { printf("FAIL t14b unterminated name allowed\n"); return 1; }
	printf("PASS t14 unterminated buffers rejected\n");

	/* 15 M13: path policy — purpose whitelist + hardened levels. */
	s_confirm_answer = 1; s_confirms = 0;
	uint32_t p84[3] = { 0x80000000u | 84, 0x80000000u | 60, 0x80000000u | 0 };
	o = os_signsvc_delegate("eth", tx, n, p84, 3, confirm_ui);
	if (o.result != OS_SIGN_OK) { printf("FAIL t15 purpose84 rc=%d\n", o.result); return 1; }
	/* non-hardened coin must be refused */
	uint32_t pnoh[3] = { 0x80000000u | 44, 60, 0x80000000u | 0 };
	o = os_signsvc_delegate("eth", tx, n, pnoh, 3, confirm_ui);
	if (o.result == OS_SIGN_OK) { printf("FAIL t15b non-hardened coin signed\n"); return 1; }
	/* unknown purpose must be refused */
	uint32_t pbogus[3] = { 0x80000000u | 99, 0x80000000u | 60, 0x80000000u | 0 };
	o = os_signsvc_delegate("eth", tx, n, pbogus, 3, confirm_ui);
	if (o.result == OS_SIGN_OK) { printf("FAIL t15c bogus purpose signed\n"); return 1; }
	/* non-hardened account must be refused */
	uint32_t pacct[3] = { 0x80000000u | 44, 0x80000000u | 60, 0 };
	o = os_signsvc_delegate("eth", tx, n, pacct, 3, confirm_ui);
	if (o.result == OS_SIGN_OK) { printf("FAIL t15d non-hardened account signed\n"); return 1; }
	printf("PASS t15 path policy enforced\n");

	/* 16 catalog: list, install an optional app, coin/id guards, delete */
	if (os_app_catalog_count() == 0) { printf("FAIL t16 empty catalog\n"); return 1; }
	if (os_app_catalog_by_id("ltc") == NULL) { printf("FAIL t16a no ltc\n"); return 1; }
	if (os_app_by_id("ltc") != NULL) { printf("FAIL t16b ltc preinstalled?\n"); return 1; }
	/* install ltc (BTC-like, coin 2) */
	if (os_app_catalog_install("ltc") != 0) { printf("FAIL t16c install\n"); return 1; }
	if (os_app_by_id("ltc") == NULL) { printf("FAIL t16d not visible\n"); return 1; }
	if (os_app_by_coin(2) == NULL) { printf("FAIL t16e coin not claimed\n"); return 1; }
	/* re-install same id must fail (already installed) */
	if (os_app_catalog_install("ltc") != -1) { printf("FAIL t16f dup install\n"); return 1; }
	/* unknown catalog id */
	if (os_app_catalog_install("nosuch") != -1) { printf("FAIL t16g unknown id\n"); return 1; }
	/* installed catalog app is not core → deletable */
	if (os_app_uninstall("ltc") != 0) { printf("FAIL t16h delete\n"); return 1; }
	if (os_app_by_id("ltc") != NULL) { printf("FAIL t16i still visible\n"); return 1; }
	/* core apps must NOT be deletable */
	if (os_app_uninstall("btc") != -1) { printf("FAIL t16j core deleted\n"); return 1; }
	if (os_app_uninstall("eth") != -1) { printf("FAIL t16k core deleted\n"); return 1; }
	printf("PASS t16 catalog install/delete + core protection\n");

	printf("ALL PASS\n");
	return 0;
}
