/*
 * HardID Hardware Wallet — minimal bounded CBOR (RFC 8949)
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 */

#include "cbor.h"
#include <string.h>

void cbor_reader_init(cbor_reader_t *r, const uint8_t *data, size_t len,
                      uint32_t budget)
{
	r->data = data;
	r->len = len;
	r->pos = 0;
	r->depth = 0;
	r->budget = budget ? budget : 4096;
}

static int read_byte(const cbor_reader_t *r, size_t off, uint8_t *b)
{
	if (r->pos + off >= r->len)
		return CBOR_ERR_TRUNCATED;
	*b = r->data[r->pos + off];
	return CBOR_OK;
}

static int read_argument(cbor_reader_t *r, uint8_t info, uint64_t *val)
{
	size_t need;
	if (info < 24) {
		/* argument is the low 5 bits; consume the single header byte */
		*val = info;
		r->pos += 1;
		return CBOR_OK;
	} else if (info == 24) {
		need = 1;
	} else if (info == 25) {
		need = 2;
	} else if (info == 26) {
		need = 4;
	} else if (info == 27) {
		need = 8;
	} else {
		return CBOR_ERR_MALFORMED;  /* 28-31 reserved */
	}
	if (r->pos + 1 + need > r->len)
		return CBOR_ERR_TRUNCATED;
	uint64_t v = 0;
	for (size_t i = 0; i < need; i++)
		v = (v << 8) | r->data[r->pos + 1 + i];
	/* minimal width is enforced on decode too (canonical CTAP2) */
	if (need > 1 && v < (1ULL << (8 * (need - 1))))
		return CBOR_ERR_MALFORMED;
	*val = v;
	r->pos += 1 + need;
	return CBOR_OK;
}

int cbor_peek_type(const cbor_reader_t *r, uint8_t *type, uint8_t *info)
{
	uint8_t b;
	if (read_byte(r, 0, &b) != CBOR_OK)
		return CBOR_ERR_TRUNCATED;
	*type = b >> 5;
	*info = b & 0x1F;
	return CBOR_OK;
}

static int enter_container(cbor_reader_t *r, size_t count)
{
	/* Depth guard for the streaming cbor_read_* path. Nested containers are
	 * tracked so hostile deep nesting is rejected; the caller must pair every
	 * cbor_read_array_head/cbor_read_map_head with cbor_reader_leave() once
	 * it has consumed the container's members (see cbor.h). Sequential
	 * siblings no longer accumulate because leave() decrements on close. */
	if (count >= (size_t)r->budget)
		return CBOR_ERR_OVERFLOW;   /* count+1 > budget; budget==0 rejects
		                               all containers (no size_t underflow) */
	r->budget -= (uint32_t)count + 1;
	if (++r->depth > CBOR_MAX_DEPTH)
		return CBOR_ERR_DEPTH;
	return CBOR_OK;
}

void cbor_reader_leave(cbor_reader_t *r)
{
	if (r->depth > 0)
		r->depth--;
}

static int read_header(cbor_reader_t *r, uint8_t want_type,
                       uint64_t *arg, uint8_t *actual_type)
{
	uint8_t type, info;
	int rc = cbor_peek_type(r, &type, &info);
	if (rc != CBOR_OK)
		return rc;
	if (actual_type)
		*actual_type = type;
	if (type != want_type)
		return CBOR_ERR_TYPE;
	return read_argument(r, info, arg);
}

int cbor_read_uint(cbor_reader_t *r, uint64_t *out)
{
	uint64_t v;
	int rc = read_header(r, CBOR_TYPE_UINT, &v, NULL);
	if (rc != CBOR_OK)
		return rc;
	*out = v;
	return CBOR_OK;
}

int cbor_read_int(cbor_reader_t *r, int64_t *out)
{
	uint8_t type, info;
	int rc = cbor_peek_type(r, &type, &info);
	if (rc != CBOR_OK)
		return rc;
	uint64_t v;
	if (type == CBOR_TYPE_UINT) {
		if ((rc = read_argument(r, info, &v)) != CBOR_OK)
			return rc;
		if (v > INT64_MAX)
			return CBOR_ERR_MALFORMED;
		*out = (int64_t)v;
		return CBOR_OK;
	} else if (type == CBOR_TYPE_NINT) {
		if ((rc = read_argument(r, info, &v)) != CBOR_OK)
			return rc;
		if (v > INT64_MAX)
			return CBOR_ERR_MALFORMED;
		*out = -1 - (int64_t)v;
		return CBOR_OK;
	}
	return CBOR_ERR_TYPE;
}

static int read_byteslike_head(cbor_reader_t *r, uint8_t want,
                               const uint8_t **ptr, size_t *len)
{
	uint64_t n;
	int rc = read_header(r, want, &n, NULL);
	if (rc != CBOR_OK)
		return rc;
	if (n > r->len - r->pos)
		return CBOR_ERR_TRUNCATED;
	if (ptr)
		*ptr = r->data + r->pos;
	if (len)
		*len = (size_t)n;
	r->pos += (size_t)n;
	return CBOR_OK;
}

int cbor_read_bytes_head(cbor_reader_t *r, const uint8_t **ptr, size_t *len)
{
	return read_byteslike_head(r, CBOR_TYPE_BYTES, ptr, len);
}

int cbor_read_bytes(cbor_reader_t *r, uint8_t *out, size_t *len)
{
	const uint8_t *ptr;
	size_t n;
	int rc = read_byteslike_head(r, CBOR_TYPE_BYTES, &ptr, &n);
	if (rc != CBOR_OK)
		return rc;
	if (len && n > *len)
		return CBOR_ERR_TYPE;
	memcpy(out, ptr, n);
	if (len)
		*len = n;
	return CBOR_OK;
}

int cbor_read_text_head(cbor_reader_t *r, const uint8_t **ptr, size_t *len)
{
	return read_byteslike_head(r, CBOR_TYPE_TEXT, ptr, len);
}

int cbor_read_array_head(cbor_reader_t *r, size_t *count)
{
	uint64_t n;
	int rc = read_header(r, CBOR_TYPE_ARRAY, &n, NULL);
	if (rc != CBOR_OK)
		return rc;
	if ((rc = enter_container(r, (size_t)n)) != CBOR_OK)
		return rc;
	*count = (size_t)n;
	return CBOR_OK;
}

int cbor_read_map_head(cbor_reader_t *r, size_t *count)
{
	uint64_t n;
	int rc = read_header(r, CBOR_TYPE_MAP, &n, NULL);
	if (rc != CBOR_OK)
		return rc;
	if (n > 256)
		return CBOR_ERR_OVERFLOW;
	if ((rc = enter_container(r, (size_t)n)) != CBOR_OK)
		return rc;
	*count = (size_t)n;
	return CBOR_OK;
}

int cbor_read_bool(cbor_reader_t *r, bool *out)
{
	uint8_t type, info;
	int rc = cbor_peek_type(r, &type, &info);
	if (rc != CBOR_OK)
		return rc;
	if (type != CBOR_TYPE_EXTRA)
		return CBOR_ERR_TYPE;
	if (info == CBOR_EXTRA_TRUE) {
		r->pos++;
		*out = true;
		return CBOR_OK;
	}
	if (info == CBOR_EXTRA_FALSE) {
		r->pos++;
		*out = false;
		return CBOR_OK;
	}
	return CBOR_ERR_TYPE;
}

int cbor_read_null(cbor_reader_t *r)
{
	uint8_t type, info;
	int rc = cbor_peek_type(r, &type, &info);
	if (rc != CBOR_OK)
		return rc;
	if (type == CBOR_TYPE_EXTRA && info == CBOR_EXTRA_NULL) {
		r->pos++;
		return CBOR_OK;
	}
	return CBOR_ERR_TYPE;
}

int cbor_skip(cbor_reader_t *r)
{
	uint8_t type, info;
	int rc = cbor_peek_type(r, &type, &info);
	if (rc != CBOR_OK)
		return rc;
	switch (type) {
	case CBOR_TYPE_UINT:
	case CBOR_TYPE_NINT: {
		uint64_t v;
		return read_argument(r, info, &v);
	}
	case CBOR_TYPE_BYTES:
	case CBOR_TYPE_TEXT: {
		uint64_t n;
		if ((rc = read_argument(r, info, &n)) != CBOR_OK)
			return rc;
		if (n > r->len - r->pos)
			return CBOR_ERR_TRUNCATED;
		r->pos += (size_t)n;
		return CBOR_OK;
	}
	case CBOR_TYPE_ARRAY:
	case CBOR_TYPE_MAP: {
		uint64_t n;
		if ((rc = read_argument(r, info, &n)) != CBOR_OK)
			return rc;
		if (n > r->budget || r->depth >= CBOR_MAX_DEPTH)
			return CBOR_ERR_DEPTH;
		r->budget -= (uint32_t)n;
		r->depth++;
		size_t pairs = (type == CBOR_TYPE_MAP) ? 2 * (size_t)n : (size_t)n;
		for (size_t i = 0; i < pairs; i++) {
			if ((rc = cbor_skip(r)) != CBOR_OK) {
				r->depth--;   /* pair the ++ above even on the error path */
				return rc;
			}
		}
		r->depth--;
		return CBOR_OK;
	}
	case CBOR_TYPE_TAG: {
		uint64_t v;
		return read_argument(r, info, &v);
	}
	case CBOR_TYPE_EXTRA:
		if (info == CBOR_EXTRA_FALSE || info == CBOR_EXTRA_TRUE ||
		    info == CBOR_EXTRA_NULL) {
			r->pos++;
			return CBOR_OK;
		}
		if (info == 24) {
			r->pos++;
			return CBOR_OK;
		}
		return CBOR_ERR_MALFORMED;
	}
	return CBOR_ERR_MALFORMED;
}

/* ---- writer ---- */

void cbor_writer_init(cbor_writer_t *w, uint8_t *data, size_t cap)
{
	w->data = data;
	w->len = 0;
	w->cap = cap;
}

static int put_byte(cbor_writer_t *w, uint8_t b)
{
	if (w->len >= w->cap)
		return CBOR_ERR_OVERFLOW;
	w->data[w->len++] = b;
	return CBOR_OK;
}

static int write_header(cbor_writer_t *w, uint8_t major, uint64_t v)
{
	int rc;
	if (v < 24) {
		return put_byte(w, (uint8_t)((major << 5) | v));
	} else if (v <= 0xFF) {
		if ((rc = put_byte(w, (uint8_t)((major << 5) | 24))) != CBOR_OK)
			return rc;
		return put_byte(w, (uint8_t)v);
	} else if (v <= 0xFFFF) {
		if ((rc = put_byte(w, (uint8_t)((major << 5) | 25))) != CBOR_OK)
			return rc;
		if ((rc = put_byte(w, (uint8_t)(v >> 8))) != CBOR_OK)
			return rc;
		return put_byte(w, (uint8_t)v);
	} else if (v <= 0xFFFFFFFFu) {
		if ((rc = put_byte(w, (uint8_t)((major << 5) | 26))) != CBOR_OK)
			return rc;
		for (int i = 3; i >= 0; i--)
			if ((rc = put_byte(w, (uint8_t)(v >> (8 * i)))) != CBOR_OK)
				return rc;
		return CBOR_OK;
	} else {
		if ((rc = put_byte(w, (uint8_t)((major << 5) | 27))) != CBOR_OK)
			return rc;
		for (int i = 7; i >= 0; i--)
			if ((rc = put_byte(w, (uint8_t)(v >> (8 * i)))) != CBOR_OK)
				return rc;
		return CBOR_OK;
	}
}

int cbor_write_uint(cbor_writer_t *w, uint64_t v)
{
	return write_header(w, CBOR_TYPE_UINT, v);
}

int cbor_write_nint(cbor_writer_t *w, uint64_t abs)
{
	return write_header(w, CBOR_TYPE_NINT, abs);
}

int cbor_write_int(cbor_writer_t *w, int64_t v)
{
	if (v >= 0)
		return cbor_write_uint(w, (uint64_t)v);
	return cbor_write_nint(w, (uint64_t)(-1 - v));
}

int cbor_write_text(cbor_writer_t *w, const char *s)
{
	size_t n = strlen(s);
	int rc = write_header(w, CBOR_TYPE_TEXT, n);
	if (rc != CBOR_OK)
		return rc;
	if (w->len + n > w->cap)
		return CBOR_ERR_OVERFLOW;
	memcpy(w->data + w->len, s, n);
	w->len += n;
	return CBOR_OK;
}

int cbor_write_bytes(cbor_writer_t *w, const uint8_t *b, size_t n)
{
	int rc = write_header(w, CBOR_TYPE_BYTES, n);
	if (rc != CBOR_OK)
		return rc;
	if (w->len + n > w->cap)
		return CBOR_ERR_OVERFLOW;
	memcpy(w->data + w->len, b, n);
	w->len += n;
	return CBOR_OK;
}

int cbor_write_array_head(cbor_writer_t *w, size_t n)
{
	return write_header(w, CBOR_TYPE_ARRAY, n);
}

int cbor_write_map_head(cbor_writer_t *w, size_t n)
{
	return write_header(w, CBOR_TYPE_MAP, n);
}

int cbor_write_bool(cbor_writer_t *w, bool v)
{
	return put_byte(w, (uint8_t)((CBOR_TYPE_EXTRA << 5) |
	                            (v ? CBOR_EXTRA_TRUE : CBOR_EXTRA_FALSE)));
}

int cbor_write_null(cbor_writer_t *w)
{
	return put_byte(w, (uint8_t)((CBOR_TYPE_EXTRA << 5) | CBOR_EXTRA_NULL));
}