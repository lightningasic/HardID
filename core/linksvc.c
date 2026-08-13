/*
 * HardID Hardware Wallet — host-link service (firmware side)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include <string.h>

#include "linksvc.h"
#include "linkproto.h"
#include "signsvc.h"
#include "se_driver.h"

static uint32_t rd_u32be(const uint8_t *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	       ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

int hd_link_serve(bool (*ui_confirm_tx)(const os_tx_intent *),
                  uint8_t type, uint16_t seq,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t out_max)
{
	switch (type) {
	case HD_CMD_SIGN: {
		/* Structured SIGN request (PRD §3.4):
		 *   app_id_len | app_id | path_len | path* (u32 BE) | tx */
		size_t off = 0;
		if (!payload || plen < 2) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}
		size_t app_len = payload[off++];
		if (app_len == 0 || app_len > HD_LINK_APP_ID_MAX ||
		    plen < off + app_len + 1u) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}
		char app_id[HD_LINK_APP_ID_MAX + 1];
		memcpy(app_id, payload + off, app_len);
		app_id[app_len] = '\0';
		off += app_len;

		size_t path_len = payload[off++];
		if (path_len == 0 || path_len > HD_LINK_PATH_MAX ||
		    plen < off + path_len * 4u) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}
		uint32_t path[HD_LINK_PATH_MAX];
		for (size_t i = 0; i < path_len; i++) {
			path[i] = rd_u32be(payload + off);
			off += 4u;
		}
		size_t tx_len = plen - off;
		if (tx_len == 0) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}

		/* Provisioning gate: a wiped device never signs. */
		const se_driver_t *se = se_active();
		if (!se) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq,
			                           HD_ERR_INTERNAL, NULL, 0,
			                           out, out_max);
		}
		bool initd = false;
		if (se->is_initialized)
			se->is_initialized(&initd);
		if (!initd) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_STATE,
			                           NULL, 0, out, out_max);
		}

		/* Delegate through the SAME sign service as the on-device SIGN
		 * menu: app lookup + coin/path isolation + firmware-independent
		 * intent re-derivation + WYSIWYS confirm + real chain sighash
		 * + SE sign. A NULL confirm is a hard abort (never a bypass). */
		os_sign_outcome oc =
			os_signsvc_delegate(app_id, payload + off, tx_len,
			                    path, path_len, ui_confirm_tx);
		switch (oc.result) {
		case OS_SIGN_OK: {
			/* Reply: sig_count(4 BE) | [ sig64(64) | recid(1) ] × sig_count.
			 * Carries EVERY input's compact signature, not just the first,
			 * so a multi-input BTC PSBT is fully deliverable to the host
			 * (the host assembles witnesses from these via core/tx_asm.c). */
			uint8_t rp[4 + OS_PSBT_MAX_INPUTS * (64 + 1)];
			size_t n = 0;
			uint32_t cnt = oc.sig_count;
			rp[n++] = (uint8_t)(cnt >> 24);
			rp[n++] = (uint8_t)(cnt >> 16);
			rp[n++] = (uint8_t)(cnt >> 8);
			rp[n++] = (uint8_t)(cnt & 0xFFu);
			for (uint32_t i = 0; i < cnt; i++) {
				/* EVM's single signature lives in sig64/recid; BTC's
				 * per-input signatures live in sigs[]/recids[] (with
				 * sigs[0] also mirrored into sig64). */
				const uint8_t *s = (oc.sig_count == 1) ? oc.sig64
				                                       : oc.sigs[i];
				uint8_t r = (oc.sig_count == 1) ? oc.recid : oc.recids[i];
				memcpy(rp + n, s, 64); n += 64;
				rp[n++] = r;
			}
			return hd_link_frame_reply(HD_REPLY_OK, seq, 0, rp, n,
			                           out, out_max);
		}
		case OS_SIGN_LOCKED:
		case OS_SIGN_REJECTED:
		case OS_SIGN_ABORT:
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_AUTH,
			                           NULL, 0, out, out_max);
		case OS_SIGN_DISABLED:
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_STATE,
			                           NULL, 0, out, out_max);
		case OS_SIGN_PARSE_ERR:
		default:
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}
	}

	default:
		/* Single-verb contract (PRD §3.4): the ONLY callable operation is
		 * SIGN; any other command type — old PING/STATUS, unknown verbs,
		 * anything — is rejected outright. The device does nothing else. */
		return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
		                           NULL, 0, out, out_max);
	}
}
