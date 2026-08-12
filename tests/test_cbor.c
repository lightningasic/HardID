/* Bounded CBOR decoder/encoder tests (RFC 8949, canonical form). */
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include "../core/cbor.h"

#include "../core/cbor.c"

static int npass, nfail;
#define CHECK(cond, name) do { \
	if (cond) { npass++; printf("PASS %s\n", name); } \
	else { nfail++; printf("FAIL %s\n", name); } \
} while (0)

int main(void)
{
	/* ---- t1 canonical writer: small ints, strings, maps ---- */
	uint8_t buf[512];
	cbor_writer_t w;
	cbor_writer_init(&w, buf, sizeof buf);
	int r = 0;
	r |= cbor_write_map_head(&w, 3);
	r |= cbor_write_uint(&w, 1);
	r |= cbor_write_array_head(&w, 1);
	r |= cbor_write_text(&w, "FIDO_2_0");
	r |= cbor_write_uint(&w, 3);
	r |= cbor_write_bytes(&w, (const uint8_t *)"\xaa\xbb\xcc", 3);
	r |= cbor_write_uint(&w, 5);
	r |= cbor_write_uint(&w, 7609);
	CHECK(r == CBOR_OK, "t1 write ok");
	/* A1 01 81 68 46 49 44 4f 5f 32 5f 30 03 43 aa bb cc 05 19 1d b9 */
	uint8_t expect[] = {0xa3, 0x01, 0x81, 0x68, 'F', 'I', 'D', 'O', '_',
	                     '2', '_', '0', 0x03, 0x43, 0xaa, 0xbb, 0xcc,
	                     0x05, 0x19, 0x1d, 0xb9};
	CHECK(w.len == sizeof expect && memcmp(buf, expect, sizeof expect) == 0,
	      "t1 canonical encoding matches reference");
	/* map keys emitted in ascending order by the caller (documented) */

	/* ---- t2 decode the same document ---- */
	cbor_reader_t rd;
	cbor_reader_init(&rd, buf, w.len, 128);
	uint64_t mm;
	CHECK(cbor_read_map_head(&rd, &mm) == CBOR_OK && mm == 3, "t2 map head");
	uint64_t k, v;
	CHECK(cbor_read_uint(&rd, &k) == CBOR_OK && k == 1, "t2 key 1");
	uint64_t cnt;
	CHECK(cbor_read_array_head(&rd, &cnt) == CBOR_OK && cnt == 1, "t2 arr head");
	const uint8_t *s;
	size_t sl;
	CHECK(cbor_read_text_head(&rd, &s, &sl) == CBOR_OK && sl == 8 &&
	      memcmp(s, "FIDO_2_0", 8) == 0, "t2 text");
	CHECK(cbor_read_uint(&rd, &k) == CBOR_OK && k == 3, "t2 key 3");
	size_t bl;
	uint8_t bs[16] = {0};
	CHECK(cbor_read_bytes_head(&rd, &s, &bl) == CBOR_OK && bl == 3 &&
	      memcmp(s, "\xaa\xbb\xcc", 3) == 0, "t2 bytes");
	CHECK(cbor_read_uint(&rd, &k) == CBOR_OK && k == 5, "t2 key 5");
	CHECK(cbor_read_uint(&rd, &v) == CBOR_OK && v == 7609, "t2 uint 7609");
	(void)bs;

	/* ---- t3 negative ints ---- */
	cbor_writer_init(&w, buf, sizeof buf);
	r = cbor_write_int(&w, -7);
	r |= cbor_write_int(&w, -1);
	r |= cbor_write_int(&w, 0);
	CHECK(r == CBOR_OK && buf[0] == 0x26 && buf[1] == 0x20 && buf[2] == 0x00,
	      "t3 nint -7, -1, 0");
	cbor_reader_init(&rd, buf, 3, 8);
	int64_t iv;
	CHECK(cbor_read_int(&rd, &iv) == CBOR_OK && iv == -7, "t3 read -7");
	CHECK(cbor_read_int(&rd, &iv) == CBOR_OK && iv == -1, "t3 read -1");
	CHECK(cbor_read_int(&rd, &iv) == CBOR_OK && iv == 0, "t3 read 0");

	/* ---- t4 bool/null ---- */
	cbor_writer_init(&w, buf, sizeof buf);
	r = cbor_write_bool(&w, true);
	r |= cbor_write_bool(&w, false);
	r |= cbor_write_null(&w);
	CHECK(r == CBOR_OK && buf[0] == 0xf5 && buf[1] == 0xf4 && buf[2] == 0xf6,
	      "t4 bool/null canonical");
	cbor_reader_init(&rd, buf, 3, 8);
	bool b;
	CHECK(cbor_read_bool(&rd, &b) == CBOR_OK && b == true, "t4 read true");
	CHECK(cbor_read_bool(&rd, &b) == CBOR_OK && b == false, "t4 read false");
	CHECK(cbor_read_null(&rd) == CBOR_OK, "t4 read null");

	/* ---- t5 non-canonical multi-byte int is still decodable, but depth
	 * guard rejects deeply nested input ---- */
	/* 0x01 encoded as 0x18 0x01 is non-canonical; our reader accepts it
	 * (lenient decode) while the writer always emits minimal form. */
	uint8_t nc[] = {0x18, 0x01};
	cbor_reader_init(&rd, nc, 2, 8);
	CHECK(cbor_read_uint(&rd, &v) == CBOR_OK && v == 1, "t5 lenient int");

	/* ---- t6 truncation/bounds ---- */
	cbor_reader_init(&rd, buf, 3, 8);
	uint8_t deep[32];
	memset(deep, 0x81, sizeof deep);   /* 32 nested arrays, no close */
	cbor_reader_init(&rd, deep, sizeof deep, 100);
	for (int i = 0; i < 8; i++)
		cbor_read_array_head(&rd, &mm);   /* stay under depth limit */
	int rc = cbor_read_array_head(&rd, &mm);
	CHECK(rc != CBOR_OK, "t6 depth guard trips past 8");

	/* truncated byte string header claims bytes we don't have */
	uint8_t trunc[] = {0x42, 0x01};
	cbor_reader_init(&rd, trunc, 2, 8);
	rc = cbor_read_bytes(&rd, bs, &bl);
	CHECK(rc != CBOR_OK, "t6 truncated bytes rejected");
	/* item budget 1 refuses a container (needs 1 for head + count) */
	uint8_t one[] = {0x81, 0x00};   /* [0] */
	cbor_reader_init(&rd, one, 2, 1);
	rc = cbor_read_array_head(&rd, &mm);
	CHECK(rc != CBOR_OK, "t6 item budget exhausted");

	/* ---- t7 empty map/array round trip ---- */
	cbor_writer_init(&w, buf, sizeof buf);
	r = cbor_write_map_head(&w, 0);
	r |= cbor_write_array_head(&w, 0);
	CHECK(r == CBOR_OK && buf[0] == 0xa0 && buf[1] == 0x80, "t7 empty map/arr");
	cbor_reader_init(&rd, buf, 2, 8);
	CHECK(cbor_read_map_head(&rd, &mm) == CBOR_OK && mm == 0, "t7 empty map");
	CHECK(cbor_read_array_head(&rd, &mm) == CBOR_OK && mm == 0, "t7 empty arr");

	/* ---- t8 write capacity overflow ---- */
	cbor_writer_init(&w, buf, 0);
	r = cbor_write_uint(&w, 0);
	CHECK(r == CBOR_ERR_OVERFLOW, "t8 write overflow");

	printf("\nCBOR: %d pass, %d fail\n", npass, nfail);
	return nfail ? 1 : 0;
}