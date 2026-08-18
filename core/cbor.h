/*
 * HardID Hardware Wallet — minimal bounded CBOR (RFC 8949)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * A small, deterministic, bounds-checked CBOR encoder/decoder used by the
 * CTAP2 protocol layer (core/ctap2.c). Attack-surface policy (design doc
 * 09 §9): decoding is bounded by a caller-provided buffer, item budget and
 * nesting depth; overflow returns CTAP2_ERR_INVALID_CBOR/INVALID_PARAMETER
 * instead of writing past the end. Only the subset needed by CTAP2 is
 * implemented: unsigned/negative ints, byte strings, text strings,
 * arrays, maps, true/false/null. Encoder emits canonical form (minimal
 * int widths); map keys must be emitted in ascending order by the caller
 * as required for CTAP2 responses.
 */

#ifndef HARDID_CBOR_H
#define HARDID_CBOR_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "fido.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- decoder error codes (CTAP2 status bytes) ---- */
#define CBOR_OK                 0
#define CBOR_ERR_TRUNCATED      (CTAP2_ERR_INVALID_CBOR)
#define CBOR_ERR_MALFORMED      (CTAP2_ERR_INVALID_CBOR)
#define CBOR_ERR_TYPE           (CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
#define CBOR_ERR_DEPTH          (CTAP2_ERR_CBOR_UNEXPECTED_TYPE)
#define CBOR_ERR_OVERFLOW       (CTAP2_ERR_CBOR_UNEXPECTED_TYPE)

#define CBOR_TYPE_UINT    0
#define CBOR_TYPE_NINT    1
#define CBOR_TYPE_BYTES   2
#define CBOR_TYPE_TEXT    3
#define CBOR_TYPE_ARRAY   4
#define CBOR_TYPE_MAP     5
#define CBOR_TYPE_TAG     6
#define CBOR_TYPE_EXTRA   7
#define CBOR_EXTRA_FALSE  20
#define CBOR_EXTRA_TRUE   21
#define CBOR_EXTRA_NULL   22

/* Nesting + element budget guards against deep/wide hostile CBOR. */
#define CBOR_MAX_DEPTH 8

typedef struct {
	const uint8_t *data;
	size_t        len;
	size_t        pos;
	unsigned      depth;
	uint32_t      budget;   /* remaining decodable items, caller-set */
} cbor_reader_t;

typedef struct {
	uint8_t *data;
	size_t   len;    /* bytes written so far */
	size_t   cap;    /* total capacity */
} cbor_writer_t;

void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len,
                      uint32_t budget);
/* Advance one item (decode header). Returns CBOR_OK or CBOR_ERR_*. */
int cbor_peek_type(const cbor_reader_t *r, uint8_t *type, uint8_t *info);
int cbor_skip(cbor_reader_t *r);

/* Read a value. out points to a uint64 for ints, or to the item length
 * place for bytes/text/array/map. For bytes/text the data pointer is
 * exposed via r after the call (ptr stored in *out32? no) — see below. */
int cbor_read_uint(cbor_reader_t *r, uint64_t *out);         /* major 0 */
int cbor_read_int(cbor_reader_t *r, int64_t *out);           /* 0 or 1 */
int cbor_read_bytes_head(cbor_reader_t *r, const uint8_t **ptr,
                         size_t *len);                       /* major 2 */
int cbor_read_bytes(cbor_reader_t *r, uint8_t *out, size_t *len);
int cbor_read_text_head(cbor_reader_t *r, const uint8_t **ptr, size_t *len);
int cbor_read_array_head(cbor_reader_t *r, size_t *count);
int cbor_read_map_head(cbor_reader_t *r, size_t *count);
/* Close the container opened by the most recent cbor_read_array_head/
 * cbor_read_map_head after its members have been consumed. Pairs the depth
 * increment done in enter_container() so sequential sibling containers do
 * not accumulate depth. Nested depth is still bounded by CBOR_MAX_DEPTH. */
void cbor_reader_leave(cbor_reader_t *r);
int cbor_read_bool(cbor_reader_t *r, bool *out);
int cbor_read_null(cbor_reader_t *r);

/* Writer (canonical minimal-width encoding). Return CBOR_OK or
 * CBOR_ERR_OVERFLOW when the buffer is exhausted. */
void cbor_writer_init(cbor_writer_t *w, uint8_t *data, size_t cap);
int cbor_write_uint(cbor_writer_t *w, uint64_t v);
int cbor_write_nint(cbor_writer_t *w, uint64_t abs);          /* -1-abs */
int cbor_write_int(cbor_writer_t *w, int64_t v);
int cbor_write_text(cbor_writer_t *w, const char *s);
int cbor_write_bytes(cbor_writer_t *w, const uint8_t *b, size_t n);
int cbor_write_array_head(cbor_writer_t *w, size_t n);
int cbor_write_map_head(cbor_writer_t *w, size_t n);
int cbor_write_bool(cbor_writer_t *w, bool v);
int cbor_write_null(cbor_writer_t *w);

#ifdef __cplusplus
}
#endif

#endif /* HARDID_CBOR_H */