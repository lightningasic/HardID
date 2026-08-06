/*
 * HardID Hardware Wallet — host-link service (firmware side)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "linksvc.h"
#include "linkproto.h"

int hd_link_serve(const hd_link_se_t *se,
                  bool (*ui_confirm_digest)(const uint8_t *digest32),
                  uint8_t type, uint16_t seq,
                  const uint8_t *payload, size_t plen,
                  uint8_t *out, size_t out_max)
{
	switch (type) {
	case HD_CMD_PING: {
		uint8_t pong[1] = { 0x50 }; /* 'P' */
		return hd_link_frame_reply(HD_REPLY_OK, seq, 0, pong, 1, out, out_max);
	}

	case HD_CMD_STATUS: {
		uint8_t st[1] = { (uint8_t)(se && se->is_initialized() ? 1 : 0) };
		return hd_link_frame_reply(HD_REPLY_OK, seq, 0, st, 1, out, out_max);
	}

	case HD_CMD_SIGN: {
		if (!se || !se->sign) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_INTERNAL,
			                           NULL, 0, out, out_max);
		}
		/* payload is a bare 32-byte digest */
		if (!payload || plen != 32) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
			                           NULL, 0, out, out_max);
		}
		if (!se->is_initialized()) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_STATE,
			                           NULL, 0, out, out_max);
		}
		/* On-device Clear Sign: show the digest, get user confirmation. A
		 * session unlock must have happened already; if not, the wrapper
		 * refused and we leak nothing. */
		if (!ui_confirm_digest || !ui_confirm_digest(payload)) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_AUTH,
			                           NULL, 0, out, out_max);
		}
		uint8_t sig[64];
		int rc = se->sign(payload, sig);
		if (rc != 0) {
			return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_AUTH,
			                           NULL, 0, out, out_max);
		}
		return hd_link_frame_reply(HD_REPLY_OK, seq, 0, sig, 64, out, out_max);
	}

	default:
		return hd_link_frame_reply(HD_REPLY_ERR, seq, HD_ERR_PARAM,
		                           NULL, 0, out, out_max);
	}
}