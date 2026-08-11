/*
 * HardID Hardware Wallet — secp256r1 (P-256) field + point arithmetic
 * Copyright (C) 2026 LightningASIC / HardID contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * 256-bit arithmetic using 4x64 limbs with unsigned __int128 products.
 * Jacobian coordinates for point ops. Curve y^2 = x^3 - 3x + b (a = -3,
 * so the Jacobian double uses E = 3*(X^2-Z^4)). NOT constant-time.
 */

#include "secp256r1.h"
#include "rfc6979.h"
#include "secure_zero.h"
#include <string.h>

#if !defined(__SIZEOF_INT128__)
#error "secp256r1 implementation requires __int128 support"
#endif

typedef unsigned __int128 u128;

/* field prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1 */
typedef struct { uint64_t v[4]; } fe;   /* little-endian limbs, mod p */
typedef struct { uint64_t v[4]; } scalar;

static const uint64_t P[4] = {
	0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFFULL,
	0x0000000000000000ULL, 0xFFFFFFFF00000001ULL
};
static const uint64_t N[4] = {   /* group order */
	0xF3B9CAC2FC632551ULL, 0xBCE6FAADA7179E84ULL,
	0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFF00000000ULL
};
static const uint64_t GX[4] = {  /* G.x, little-endian 64-bit limbs */
	0xF4A13945D898C296ULL, 0x77037D812DEB33A0ULL,
	0xF8BCE6E563A440F2ULL, 0x6B17D1F2E12C4247ULL
};
static const uint64_t GY[4] = {  /* G.y, little-endian 64-bit limbs */
	0xCBB6406837BF51F5ULL, 0x2BCE33576B315ECEULL,
	0x8EE7EB4A7C0F9E16ULL, 0x4FE342E2FE1A7F9BULL
};
static const uint64_t B[4] = {   /* curve constant b */
	0x3BCE3C3E27D2604BULL, 0x651D06B0CC53B0F6ULL,
	0xB3EBBD55769886BCULL, 0x5AC635D8AA3A93E7ULL
};

/* reduction constant C = 2^256 - p (5 limbs, LE) */
static const uint64_t CP[5] = {
	0x0000000000000001ULL, 0xFFFFFFFF00000000ULL,
	0xFFFFFFFFFFFFFFFFULL, 0x00000000FFFFFFFEULL, 0x0ULL
};
/* reduction constant 2^256 - n (5 limbs, LE) */
static const uint64_t CN[5] = {
	0x0C46353D039CDAAFULL, 0x4319055258E8617BULL,
	0x0ULL, 0x00000000FFFFFFFFULL, 0x0ULL
};
/* (p+1)/4, used as the exponent for y = sqrt(x) since p ≡ 3 (mod 4) */
static const uint64_t E_SQRT[4] = {
	0x0000000000000000ULL, 0x0000000040000000ULL,
	0x4000000000000000ULL, 0x3FFFFFFFC0000000ULL
};

/* ---- 256-bit helpers ---- */

static void fe_copy(fe *r, const fe *a) { memcpy(r->v, a->v, 32); }
static void fe_zero(fe *r) { memset(r->v, 0, 32); }
static bool fe_is_zero(const fe *a) { return (a->v[0]|a->v[1]|a->v[2]|a->v[3]) == 0; }

static int cmp256(const uint64_t *a, const uint64_t *b)
{
	for (int i = 3; i >= 0; i--) {
		if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
	}
	return 0;
}

/* r = a - b (assumes a >= b); alias-safe for r == a or r == b */
static void sub256(uint64_t *r, const uint64_t *a, const uint64_t *b)
{
	uint64_t borrow = 0;
	for (int i = 0; i < 4; i++) {
		uint64_t ai = a[i];            /* read before any write (aliasing) */
		uint64_t bi = b[i] + borrow;
		uint64_t nb = (bi < borrow);
		uint64_t di = ai - bi;
		borrow = (ai < bi) | nb;
		r[i] = di;
	}
}

static void fe_reduce(fe *a)
{
	if (cmp256(a->v, P) >= 0)
		sub256(a->v, a->v, P);
}

/* r = (a + b) mod p */
static void fe_add(fe *r, const fe *a, const fe *b)
{
	uint64_t carry = 0;
	for (int i = 0; i < 4; i++) {
		u128 s = (u128)a->v[i] + b->v[i] + carry;
		r->v[i] = (uint64_t)s;
		carry = (uint64_t)(s >> 64);
	}
	/* if carry or r >= p, subtract p once; r < 2p so one pass suffices */
	if (carry || cmp256(r->v, P) >= 0) {
		if (carry) {
			/* r = r + 2^256 - p = r + CP (mod p); CP < 2^256, r < 2^256 */;
			uint64_t acc = 0;
			for (int i = 0; i < 4; i++) {
				u128 s = (u128)r->v[i] + CP[i] + acc;
				r->v[i] = (uint64_t)s;
				acc = (uint64_t)(s >> 64);
			}
			(void)acc;
		} else {
			sub256(r->v, r->v, P);
		}
	}
	/* defensive: result may still be >= p? r < 2p always after above; but
	 * carry path yields r + CP which is < 2^256, and CP < p so result < p? */
	if (cmp256(r->v, P) >= 0)
		sub256(r->v, r->v, P);
}

/* r = (a - b) mod p */
static void fe_sub(fe *r, const fe *a, const fe *b)
{
	if (cmp256(a->v, b->v) >= 0) {
		sub256(r->v, a->v, b->v);
	} else {
		/* a + p - b */
		fe t;
		uint64_t carry = 0;
		for (int i = 0; i < 4; i++) {
			u128 s = (u128)a->v[i] + P[i] + carry;
			t.v[i] = (uint64_t)s;
			carry = (uint64_t)(s >> 64);
		}
		sub256(r->v, t.v, b->v);
	}
}

/* reduce a 512-bit value (t[0..7], LE) mod a modulus m, using
 * C = 2^256 - m. Identity: 2^256 ≡ C (mod m), so fold high limbs by
 * multiply-by-C until only 256 bits remain, then conditional-subtract. */
static void reduce512(const uint64_t t[8], const uint64_t m[4],
		      const uint64_t c[5], uint64_t out[4])
{
	uint64_t rem[12] = {0};
	memcpy(rem, t, 64);
	for (int pass = 0; pass < 8; pass++) {
		int empty = 1;
		for (int i = 4; i < 12; i++) {
			if (rem[i]) { empty = 0; break; }
		}
		if (empty) break;
		if (pass < 7) {
			for (int i = 7; i >= 4; i--) {
				uint64_t h = rem[i];
				if (!h) continue;
				rem[i] = 0;
				uint64_t carry = 0;
				for (int j = 0; j < 5; j++) {
					int idx = (i - 4) + j;
					if (idx >= 12) break;
					u128 cur = (u128)h * c[j] + rem[idx] + carry;
					rem[idx] = (uint64_t)cur;
					carry = (uint64_t)(cur >> 64);
				}
				int idx = (i - 4) + 5;
				while (carry && idx < 12) {
					u128 cur = (u128)rem[idx] + carry;
					rem[idx] = (uint64_t)cur;
					carry = (uint64_t)(cur >> 64);
					idx++;
				}
			}
		}
	}
	memcpy(out, rem, 32);
	/* conditional subtract (up to 3; result < 2^256 < 2m) */
	for (int i = 0; i < 3 && cmp256(out, m) >= 0; i++)
		sub256(out, out, m);
}

/* 512-bit multiply then reduce mod p */
static void fe_mul(fe *r, const fe *a, const fe *b)
{
	uint64_t t[8] = {0};
	for (int i = 0; i < 4; i++) {
		uint64_t carry = 0;
		for (int j = 0; j < 4; j++) {
			u128 cur = (u128)a->v[i] * b->v[j] + t[i + j] + carry;
			t[i + j] = (uint64_t)cur;
			carry = (uint64_t)(cur >> 64);
		}
		t[i + 4] = carry;
	}
	reduce512(t, P, CP, r->v);
}

static void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

/* r = a^(p-2) mod p (Fermat inverse). Square-and-multiply over p-2. */
static void fe_inv(fe *r, const fe *a)
{
	uint64_t e[4];
	sub256(e, P, (const uint64_t[]){2,0,0,0});
	fe base, res;
	fe_copy(&base, a);
	fe_zero(&res);
	res.v[0] = 1;
	for (int i = 3; i >= 0; i--) {
		for (int b = 63; b >= 0; b--) {
			fe_sqr(&res, &res);
			if ((e[i] >> b) & 1)
				fe_mul(&res, &res, &base);
		}
	}
	fe_copy(r, &res);
}

/* ---- Jacobian point ops ---- */
typedef struct { fe x, y, z; } point;   /* (X/Z^2, Y/Z^3) */

static void pt_set_infinity(point *p) { fe_zero(&p->x); fe_zero(&p->y); fe_zero(&p->z); }
static bool pt_is_infinity(const point *p) { return fe_is_zero(&p->z); }

/* P-256 has a = -3: E = 3*X^2 + a*Z^4 = 3*(X^2 - Z^4) */
static void pt_double_aff(point *r, const point *p)
{
	if (pt_is_infinity(p)) { pt_set_infinity(r); return; }
	fe a, b, c, d, e, f, t, z2, z4;
	fe_sqr(&a, &p->x);                 /* a = X^2 */
	fe_sqr(&b, &p->y);                 /* b = Y^2 */
	fe_sqr(&c, &b);                    /* c = b^2 */
	fe_add(&t, &p->x, &b); fe_sqr(&t, &t);
	fe_sub(&t, &t, &a); fe_sub(&t, &t, &c);
	fe_add(&d, &t, &t);                /* d = 2*((X+b)^2 - a - c) */
	fe_sqr(&z2, &p->z); fe_sqr(&z4, &z2);      /* z4 = Z^4 */
	fe_sub(&t, &a, &z4);               /* t = X^2 - Z^4 */
	fe_add(&e, &t, &t); fe_add(&e, &e, &t);    /* e = 3*(X^2 - Z^4) */
	fe_sqr(&f, &e);                    /* f = e^2 */
	fe_add(&t, &d, &d);
	fe_sub(&r->x, &f, &t);             /* X' = f - 2d */
	fe_sub(&t, &d, &r->x);
	fe_mul(&t, &e, &t);
	fe_add(&c, &c, &c); fe_add(&c, &c, &c); fe_add(&c, &c, &c); /* 8c */
	fe_sub(&r->y, &t, &c);             /* Y' = e*(d-X') - 8c */
	fe_mul(&t, &p->y, &p->z);
	fe_add(&r->z, &t, &t);             /* Z' = 2YZ */
}

static void pt_double(point *r, const point *p)
{
	/* alias-safe: operate on a local copy when r == p */
	if (r == p) {
		point tmp;
		pt_double_aff(&tmp, p);
		*r = tmp;
	} else {
		pt_double_aff(r, p);
	}
}

static void pt_add(point *r, const point *p, const point *q)
{
	if (pt_is_infinity(p)) { *r = *q; return; }
	if (pt_is_infinity(q)) { *r = *p; return; }
	fe z1z1, z2z2, u1, u2, s1, s2, h, i, j, rr, v, t;
	fe_sqr(&z1z1, &p->z);
	fe_sqr(&z2z2, &q->z);
	fe_mul(&u1, &p->x, &z2z2);
	fe_mul(&u2, &q->x, &z1z1);
	fe_mul(&t, &q->z, &z2z2);
	fe_mul(&s1, &p->y, &t);
	fe_mul(&t, &p->z, &z1z1);
	fe_mul(&s2, &q->y, &t);
	fe_sub(&h, &u2, &u1);
	if (fe_is_zero(&h)) {
		fe_sub(&t, &s2, &s1);
		if (fe_is_zero(&t)) pt_double(r, p);
		else pt_set_infinity(r);
		return;
	}
	fe_add(&i, &h, &h); fe_sqr(&i, &i);
	fe_mul(&j, &h, &i);
	fe_sub(&t, &s2, &s1);
	fe_add(&rr, &t, &t);
	fe_mul(&v, &u1, &i);
	fe_sqr(&t, &rr);
	fe_sub(&r->x, &t, &j);
	fe_add(&u2, &v, &v);
	fe_sub(&r->x, &r->x, &u2);         /* X' = r^2 - j - 2v */
	fe_sub(&u2, &v, &r->x);
	fe_mul(&u2, &rr, &u2);
	fe_mul(&t, &s1, &j);
	fe_add(&t, &t, &t);
	fe_sub(&r->y, &u2, &t);            /* Y' = r*(v-X') - 2*s1*j */
	fe_add(&t, &p->z, &q->z);
	fe_sqr(&t, &t);
	fe_sub(&t, &t, &z1z1);
	fe_sub(&t, &t, &z2z2);
	fe_mul(&r->z, &t, &h);             /* Z' = ((Z1+Z2)^2 - Z1Z1 - Z2Z2)*h */
}

/* scalar mult: r = k * G (k is 32-byte big-endian) */
static void pt_mul_gen(point *r, const uint8_t *k)
{
	point g;
	memcpy(g.x.v, GX, 32);
	memcpy(g.y.v, GY, 32);
	fe_zero(&g.z); g.z.v[0] = 1;
	point acc;
	pt_set_infinity(&acc);
	for (int i = 0; i < 32; i++) {
		for (int b = 7; b >= 0; b--) {
			pt_double(&acc, &acc);
			if ((k[i] >> b) & 1) {
				point t = acc;
				pt_add(&acc, &t, &g);
			}
		}
	}
	*r = acc;
}

/* to affine + serialize uncompressed (0x04 || X || Y) */
static void pt_serialize_uncompressed(const point *p, uint8_t *out65)
{
	fe zinv, zinv2, zinv3, ax, ay;
	fe_inv(&zinv, &p->z);
	fe_sqr(&zinv2, &zinv);
	fe_mul(&zinv3, &zinv2, &zinv);
	fe_mul(&ax, &p->x, &zinv2);
	fe_mul(&ay, &p->y, &zinv3);
	fe_reduce(&ax);
	fe_reduce(&ay);
	out65[0] = 0x04;
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 8; j++)
			out65[1 + i*8 + j] = (uint8_t)(ax.v[3 - i] >> ((7 - j) * 8));
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 8; j++)
			out65[33 + i*8 + j] = (uint8_t)(ay.v[3 - i] >> ((7 - j) * 8));
}

static bool scalar_valid(const uint8_t *k)
{
	/* k != 0 and k < n */
	bool nonzero = false;
	for (int i = 0; i < 32; i++) if (k[i]) nonzero = true;
	if (!nonzero) return false;
	uint8_t nbe[32];
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 8; j++)
			nbe[i*8 + j] = (uint8_t)(N[3 - i] >> ((7 - j) * 8));
	for (int i = 0; i < 32; i++) {
		if (k[i] != nbe[i]) return k[i] < nbe[i];
	}
	return false; /* equal => invalid */
}

int os_secp256r1_pubkey(const uint8_t *priv32, uint8_t *pub65)
{
	if (!scalar_valid(priv32))
		return -1;
	point r;
	pt_mul_gen(&r, priv32);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_uncompressed(&r, pub65);
	return 0;
}

/* ---- scalar arithmetic mod n (big-endian 32-byte) ---- */

static void be_to_limbs(const uint8_t *be, uint64_t *limbs4)
{
	for (int i = 0; i < 4; i++) {
		uint64_t v = 0;
		for (int j = 0; j < 8; j++)
			v = (v << 8) | be[(3 - i) * 8 + j];
		limbs4[i] = v;
	}
}
static void limbs_to_be(const uint64_t *limbs4, uint8_t *be)
{
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 8; j++)
			be[(3 - i) * 8 + j] = (uint8_t)(limbs4[i] >> ((7 - j) * 8));
}

void os_secp256r1_scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint64_t al[4], bl[4], t[8] = {0};
	be_to_limbs(a, al);
	be_to_limbs(b, bl);
	for (int i = 0; i < 4; i++) {
		uint64_t carry = 0;
		for (int j = 0; j < 4; j++) {
			u128 cur = (u128)al[i] * bl[j] + t[i + j] + carry;
			t[i + j] = (uint64_t)cur;
			carry = (uint64_t)(cur >> 64);
		}
		t[i + 4] = carry;
	}
	uint64_t out[4];
	reduce512(t, N, CN, out);
	limbs_to_be(out, r);
}

void os_secp256r1_scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b)
{
	uint64_t al[4], bl[4], s[4];
	be_to_limbs(a, al);
	be_to_limbs(b, bl);
	uint64_t carry = 0;
	for (int i = 0; i < 4; i++) {
		u128 cur = (u128)al[i] + bl[i] + carry;
		s[i] = (uint64_t)cur;
		carry = (uint64_t)(cur >> 64);
	}
	/* if carry or s >= n, subtract n */
	if (carry) {
		/* s + 2^256 - n = s + CN mod n */
		uint64_t acc = 0;
		for (int i = 0; i < 4; i++) {
			u128 v = (u128)s[i] + CN[i] + acc;
			s[i] = (uint64_t)v;
			acc = (uint64_t)(v >> 64);
		}
		(void)acc;
	} else if (cmp256(s, N) >= 0) {
		sub256(s, s, N);
	}
	if (cmp256(s, N) >= 0)
		sub256(s, s, N);
	limbs_to_be(s, r);
}

int os_secp256r1_scalar_inv(uint8_t *r, const uint8_t *a)
{
	/* a^(n-2) mod n via square-and-multiply (reuses scalar_mul) */
	int nonzero = 0;
	for (int i = 0; i < 32; i++) if (a[i]) nonzero = 1;
	if (!nonzero) return -1;

	uint8_t res[32] = {0}, base[32];
	res[31] = 1;
	memcpy(base, a, 32);
	/* exponent n-2 (big-endian) */
	uint8_t nbe[32] = OS_SECP256R1_ORDER_NBE32;
	int borrow = 0;
	for (int i = 31; i >= 0; i--) {
		int d = nbe[i] - (i == 31 ? 2 : 0) - borrow;
		if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
		nbe[i] = (uint8_t)d;
	}
	for (int i = 0; i < 32; i++) {
		for (int b = 7; b >= 0; b--) {
			uint8_t t[32];
			os_secp256r1_scalar_mul(t, res, res);
			memcpy(res, t, 32);
			if ((nbe[i] >> b) & 1) {
				os_secp256r1_scalar_mul(t, res, base);
				memcpy(res, t, 32);
			}
		}
	}
	memcpy(r, res, 32);
	os_secure_bzero(base, 32);
	return 0;
}

/* ---- point parse/serialize for ECDSA verify ---- */

/* y = sqrt(x^3 - 3x + b); p ≡ 3 (mod 4) so sqrt = a^((p+1)/4) */
static int fe_sqrt(fe *r, const fe *x)
{
	fe rhs, t;
	fe_sqr(&rhs, x);              /* rhs = x^3 - 3x + b */
	fe_mul(&rhs, &rhs, x);
	fe t3;
	memcpy(t3.v, (const uint64_t[]){3,0,0,0}, 32);
	fe_mul(&t, &t3, x);
	fe_sub(&rhs, &rhs, &t);
	fe_add(&rhs, &rhs, (const fe *)&B);
	/* exponent (p+1)/4 (hardcoded; p ≡ 3 mod 4 so sqrt(a) = a^((p+1)/4)) */
	uint64_t e[4] = { E_SQRT[0], E_SQRT[1], E_SQRT[2], E_SQRT[3] };
	fe base = rhs, res;
	fe_zero(&res);
	res.v[0] = 1;
	for (int i = 3; i >= 0; i--)
		for (int b = 63; b >= 0; b--) {
			fe_sqr(&res, &res);
			if ((e[i] >> b) & 1)
				fe_mul(&res, &res, &base);
		}
	/* verify res^2 == rhs */
	fe check;
	fe_sqr(&check, &res);
	if (cmp256(check.v, rhs.v) != 0)
		return -1;
	fe_copy(r, &res);
	return 0;
}

int os_secp256r1_parse_pubkey(const uint8_t *pub, size_t pub_len,
			      void *point_out)
{
	point *p = (point *)point_out;
	if (pub_len == 33 && (pub[0] == 0x02 || pub[0] == 0x03)) {
		/* x from bytes 1..32 */
		for (int i = 0; i < 4; i++) {
			uint64_t v = 0;
			for (int j = 0; j < 8; j++)
				v = (v << 8) | pub[1 + (3 - i) * 8 + j];
			p->x.v[i] = v;
		}
		if (cmp256(p->x.v, P) >= 0)
			return -1;
		if (fe_sqrt(&p->y, &p->x) != 0)
			return -1;
		int want_odd = pub[0] == 0x03;
		if ((int)(p->y.v[0] & 1) != want_odd)
			fe_sub(&p->y, (const fe*)(&(fe){ .v = {P[0],P[1],P[2],P[3]} }), &p->y);
	} else if (pub_len == 65 && pub[0] == 0x04) {
		for (int i = 0; i < 4; i++) {
			uint64_t v = 0;
			for (int j = 0; j < 8; j++)
				v = (v << 8) | pub[1 + (3 - i) * 8 + j];
			p->x.v[i] = v;
		}
		for (int i = 0; i < 4; i++) {
			uint64_t v = 0;
			for (int j = 0; j < 8; j++)
				v = (v << 8) | pub[33 + (3 - i) * 8 + j];
			p->y.v[i] = v;
		}
		if (cmp256(p->x.v, P) >= 0 || cmp256(p->y.v, P) >= 0)
			return -1;
		/* on-curve check: y^2 == x^3 - 3x + b */
		fe rhs;
		fe_sqr(&rhs, &p->x);
		fe_mul(&rhs, &rhs, &p->x);
		fe t3;
		memcpy(t3.v, (const uint64_t[]){3,0,0,0}, 32);
		fe t;
		fe_mul(&t, &t3, &p->x);
		fe_sub(&rhs, &rhs, &t);
		fe_add(&rhs, &rhs, (const fe *)&B);
		fe lhs;
		fe_sqr(&lhs, &p->y);
		if (cmp256(lhs.v, rhs.v) != 0)
			return -1;
	} else {
		return -1;
	}
	fe_zero(&p->z);
	p->z.v[0] = 1;
	return 0;
}

static void pt_mul(point *r, const point *g, const uint8_t *k32)
{
	point acc;
	pt_set_infinity(&acc);
	for (int i = 0; i < 32; i++)
		for (int b = 7; b >= 0; b--) {
			pt_double(&acc, &acc);
			if ((k32[i] >> b) & 1) {
				point t = acc;
				pt_add(&acc, &t, g);
			}
		}
	*r = acc;
}

int os_secp256r1_point_mul(const void *point_in, const uint8_t *k32,
			   uint8_t *pub65)
{
	point r;
	pt_mul(&r, (const point *)point_in, k32);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_uncompressed(&r, pub65);
	return 0;
}

int os_secp256r1_point_add(const void *a, const void *b, uint8_t *pub65)
{
	point r;
	pt_add(&r, (const point *)a, (const point *)b);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_uncompressed(&r, pub65);
	return 0;
}

/* ---- ECDSA ---- */

/* z = hash mod n (hash is 32 bytes; conditional subtract once) */
static void hash_to_scalar(const uint8_t *hash32, uint8_t *out)
{
	const uint8_t nbe[32] = OS_SECP256R1_ORDER_NBE32;
	memcpy(out, hash32, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (out[i] != nbe[i]) { ge = out[i] > nbe[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = out[i] - nbe[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			out[i] = (uint8_t)d;
		}
	}
}

/* r = x-of-(k*G) mod n: take uncompressed pubkey, strip 0x04, reduce x */
static int nonce_point_rx(const uint8_t *k32, uint8_t *rx32)
{
	const uint8_t nbe[32] = OS_SECP256R1_ORDER_NBE32;
	uint8_t pub[65];
	if (os_secp256r1_pubkey(k32, pub) != 0)
		return -1;
	memcpy(rx32, pub + 1, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (rx32[i] != nbe[i]) { ge = rx32[i] > nbe[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = rx32[i] - nbe[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			rx32[i] = (uint8_t)d;
		}
	}
	return 0;
}

static int is_zero(const uint8_t *a)
{
	for (int i = 0; i < 32; i++) if (a[i]) return 0;
	return 1;
}

int os_secp256r1_sign(const uint8_t priv32[32], const uint8_t hash32[32],
		      uint8_t sig64[64])
{
	const uint8_t nbe[32] = OS_SECP256R1_ORDER_NBE32;
	uint8_t z[32], k[32], r[32], s[32], tmp[32];
	int retry = 0;

	hash_to_scalar(hash32, z);

	for (;;) {
		if (os_rfc6979_nonce_n(nbe, priv32, hash32, retry, k) != 0)
			return -1;
		if (nonce_point_rx(k, r) != 0 || is_zero(r)) {
			retry++;
			continue;
		}
		/* s = k^-1 * (z + r*priv) mod n */
		os_secp256r1_scalar_mul(tmp, r, priv32);
		os_secp256r1_scalar_add(tmp, tmp, z);
		if (os_secp256r1_scalar_inv(k, k) != 0)
			return -1;
		os_secp256r1_scalar_mul(s, k, tmp);
		if (is_zero(s)) {
			retry++;
			continue;
		}
		break;
	}

	/* low-s normalization: if s > n/2, s = n - s */
	{
		static const uint8_t HALF_N[32] = {
			0x7F,0xFF,0xFF,0xFF,0x80,0x00,0x00,0x00,
			0x7F,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
			0xDE,0x73,0x7D,0x56,0xD3,0x8B,0xCF,0x42,
			0x79,0xDC,0xE5,0x61,0x7E,0x31,0x92,0xA8 };
		int ge = 0;
		for (int i = 0; i < 32; i++) {
			if (s[i] != HALF_N[i]) { ge = s[i] > HALF_N[i]; break; }
		}
		if (ge) {
			int borrow = 0;
			for (int i = 31; i >= 0; i--) {
				int d = nbe[i] - s[i] - borrow;
				if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
				s[i] = (uint8_t)d;
			}
		}
	}

	memcpy(sig64, r, 32);
	memcpy(sig64 + 32, s, 32);
	os_secure_bzero(z, 32);
	os_secure_bzero(k, 32);
	os_secure_bzero(tmp, 32);
	os_secure_bzero(s, 32);
	return 0;
}

int os_secp256r1_verify(const uint8_t *pub, size_t pub_len,
			const uint8_t hash32[32], const uint8_t sig64[64])
{
	const uint8_t nbe[32] = OS_SECP256R1_ORDER_NBE32;
	const uint8_t *r = sig64, *s = sig64 + 32;
	uint8_t z[32], w[32], u1[32], u2[32], tmp[32];
	uint8_t pt_buf[OS_SECP256R1_POINT_SIZE];
	uint8_t p1[65], p2[65];

	/* reject zero / >= n for r and s */
	for (int half = 0; half < 2; half++) {
		const uint8_t *v = sig64 + half * 32;
		int nonzero = 0, lt = 0;
		for (int i = 0; i < 32; i++) {
			if (v[i]) nonzero = 1;
			if (v[i] != nbe[i]) { lt = v[i] < nbe[i]; break; }
			if (i == 31) lt = 0;
		}
		if (!nonzero || !lt)
			return -1;
	}

	if (os_secp256r1_parse_pubkey(pub, pub_len, pt_buf) != 0)
		return -1;

	hash_to_scalar(hash32, z);
	/* w = s^-1, u1 = z*w, u2 = r*w */
	if (os_secp256r1_scalar_inv(w, s) != 0)
		return -1;
	os_secp256r1_scalar_mul(u1, z, w);
	os_secp256r1_scalar_mul(u2, r, w);

	/* P = u1*G + u2*pub */
	if (os_secp256r1_pubkey(u1, p1) != 0)
		return 0;
	if (os_secp256r1_point_mul(pt_buf, u2, p2) != 0)
		return 0;
	uint8_t a_buf[OS_SECP256R1_POINT_SIZE], b_buf[OS_SECP256R1_POINT_SIZE];
	uint8_t px[65];
	if (os_secp256r1_parse_pubkey(p1, 65, a_buf) != 0)
		return -1;
	if (os_secp256r1_parse_pubkey(p2, 65, b_buf) != 0)
		return -1;
	if (os_secp256r1_point_add(a_buf, b_buf, px) != 0)
		return 0;

	/* valid if (x of P) mod n == r */
	memcpy(tmp, px + 1, 32);
	int ge = 0;
	for (int i = 0; i < 32; i++) {
		if (tmp[i] != nbe[i]) { ge = tmp[i] > nbe[i]; break; }
	}
	if (ge) {
		int borrow = 0;
		for (int i = 31; i >= 0; i--) {
			int d = tmp[i] - nbe[i] - borrow;
			if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
			tmp[i] = (uint8_t)d;
		}
	}
	int valid = os_consttime_eq(tmp, r, 32) ? 1 : 0;
	os_secure_bzero(z, 32);
	os_secure_bzero(w, 32);
	os_secure_bzero(u1, 32);
	os_secure_bzero(u2, 32);
	os_secure_bzero(tmp, 32);
	return valid;
}