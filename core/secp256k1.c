/*
 * OpenShield Hardware Wallet — secp256k1 field + point arithmetic
 * Copyright (C) 2026 LightningASIC / OpenShield contributors
 *
 * Clean-room reimplementation. Not derived from TREZOR code.
 * License: Apache License 2.0
 *
 * 256-bit arithmetic using 4x64 limbs with unsigned __int128 products.
 * Jacobian coordinates for point ops. NOT constant-time (see bip32.h note).
 */

#include "secp256k1.h"
#include <string.h>

#if !defined(__SIZEOF_INT128__)
#error "secp256k1 implementation requires __int128 support"
#endif

typedef unsigned __int128 u128;

/* field prime p = 2^256 - 2^32 - 977 */
typedef struct { uint64_t v[4]; } fe;   /* little-endian limbs, mod p */
typedef struct { uint64_t v[4]; } scalar;

static const uint64_t P[4] = {
	0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};
static const uint64_t N[4] = {   /* group order */
	0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
	0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};
static const uint64_t GX[4] = {  /* G.x, little-endian 64-bit limbs */
	0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
	0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL
};
static const uint64_t GY[4] = {  /* G.y, little-endian 64-bit limbs */
	0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
	0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL
};

/* ---- 256-bit helpers ---- */

static void fe_copy(fe *r, const fe *a) { memcpy(r->v, a->v, 32); }
static void fe_zero(fe *r) { memset(r->v, 0, 32); }
static bool fe_is_zero(const fe *a) { return (a->v[0]|a->v[1]|a->v[2]|a->v[3]) == 0; }

static int fe_cmp_raw(const uint64_t *a, const uint64_t *b)
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
	if (fe_cmp_raw(a->v, P) >= 0)
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
	/* if carry or r >= p, subtract p */
	if (carry || fe_cmp_raw(r->v, P) >= 0)
		sub256(r->v, r->v, P);
}

/* r = (a - b) mod p */
static void fe_sub(fe *r, const fe *a, const fe *b)
{
	if (fe_cmp_raw(a->v, b->v) >= 0) {
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

/* 512-bit multiply then reduce mod p (simple schoolbook + shift-sub) */
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

	/* reduce 512->256: p = 2^256 - c, c = 2^32 + 977.
	 * t = L + 2^256 H  ≡  L + c*H (mod p). Iterate. */
	uint64_t c_lo = 0x1000003D1ULL; /* 2^32 + 977 */
	for (int pass = 0; pass < 3; pass++) {
		/* fold top 4 limbs into bottom */
		uint64_t hi[4] = { t[4], t[5], t[6], t[7] };
		t[4] = t[5] = t[6] = t[7] = 0;
		uint64_t carry = 0;
		for (int i = 0; i < 4; i++) {
			u128 prod = (u128)hi[i] * c_lo;
			u128 s = (u128)t[i] + (uint64_t)prod + carry;
			t[i] = (uint64_t)s;
			carry = (uint64_t)(s >> 64) + (uint64_t)(prod >> 64);
		}
		t[4] = carry;
	}
	/* final conditional subtract */
	fe res;
	memcpy(res.v, t, 32);
	for (int i = 0; i < 3 && fe_cmp_raw(res.v, P) >= 0; i++)
		sub256(res.v, res.v, P);
	fe_copy(r, &res);
}

static void fe_sqr(fe *r, const fe *a) { fe_mul(r, a, a); }

/* r = a^(p-2) mod p (Fermat inverse). Square-and-multiply over p-2. */
static void fe_inv(fe *r, const fe *a)
{
	/* exponent p-2 */
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

static void pt_double_aff(point *r, const point *p)
{
	if (pt_is_infinity(p)) { pt_set_infinity(r); return; }
	fe a, b, c, d, e, f, t;
	fe_sqr(&a, &p->x);                 /* a = X^2 */
	fe_sqr(&b, &p->y);                 /* b = Y^2 */
	fe_sqr(&c, &b);                    /* c = b^2 */
	fe_add(&t, &p->x, &b); fe_sqr(&t, &t);
	fe_sub(&t, &t, &a); fe_sub(&t, &t, &c);
	fe_add(&d, &t, &t);                /* d = 2*((X+b)^2 - a - c) */
	fe_add(&e, &a, &a); fe_add(&e, &e, &a); /* e = 3a */
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

/* to affine + serialize compressed */
static void pt_serialize_compressed(const point *p, uint8_t *out33)
{
	fe zinv, zinv2, zinv3, ax, ay;
	fe_inv(&zinv, &p->z);
	fe_sqr(&zinv2, &zinv);
	fe_mul(&zinv3, &zinv2, &zinv);
	fe_mul(&ax, &p->x, &zinv2);
	fe_mul(&ay, &p->y, &zinv3);
	fe_reduce(&ax);
	fe_reduce(&ay);
	out33[0] = (ay.v[0] & 1) ? 0x03 : 0x02;
	/* x coordinate as 32-byte big-endian: most-significant limb first */
	for (int i = 0; i < 4; i++)
		for (int j = 0; j < 8; j++)
			out33[1 + i*8 + j] = (uint8_t)(ax.v[3 - i] >> ((7 - j) * 8));
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

int os_secp256k1_pubkey(const uint8_t *priv32, uint8_t *pub33)
{
	if (!scalar_valid(priv32))
		return -1;
	point r;
	pt_mul_gen(&r, priv32);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_compressed(&r, pub33);
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

/* reduce a 512-bit product mod n by folding high limbs with the identity
 * 2^256 ≡ (2^256 - n) (mod n), then conditional-subtracting. */
static void scalar_reduce(uint64_t *t8, uint8_t *out_be)
{
	uint64_t rem[9] = {0};
	memcpy(rem, t8, 64); /* 512-bit value in rem[0..7] */
	rem[8] = 0;
	static const uint64_t NM1[5] = {  /* 2^256 - n, 5 limbs LE */
		0x402DA1732FC9BEBFULL, 0x4551231950B75FC4ULL, 0x1ULL, 0ULL, 0ULL
	};
	/* fold high limbs (4..7) into low by repeated multiply-by-(2^256-n) */
	for (int i = 7; i >= 4; i--) {
		if (rem[i] == 0) continue;
		uint64_t h = rem[i];
		rem[i] = 0;
		/* h * 2^(64*(i-4)) * (2^256 - n) added to rem */
		uint64_t carry = 0;
		for (int j = 0; j < 5; j++) {
			int idx = (i - 4) + j;
			if (idx > 8) break;
			u128 cur = (u128)h * NM1[j] + rem[idx] + carry;
			rem[idx] = (uint64_t)cur;
			carry = (uint64_t)(cur >> 64);
		}
		int idx = (i - 4) + 5;
		while (carry && idx <= 8) {
			u128 cur = (u128)rem[idx] + carry;
			rem[idx] = (uint64_t)cur;
			carry = (uint64_t)(cur >> 64);
			idx++;
		}
	}
	/* now rem[0..8] is ~260 bits; subtract n until < n */
	for (;;) {
		/* compare rem[0..3] (+rem[4] overflow) with n */
		if (rem[4] == 0 && rem[5] == 0 && rem[6] == 0 && rem[7] == 0 && rem[8] == 0) {
			int cmp = 0;
			for (int i = 3; i >= 0; i--) {
				if (rem[i] != N[i]) { cmp = rem[i] < N[i] ? -1 : 1; break; }
			}
			if (cmp < 0) break;
		}
		uint64_t borrow = 0;
		for (int i = 0; i < 4; i++) {
			uint64_t ai = rem[i], bi = N[i] + borrow;
			uint64_t nb = (bi < borrow);
			uint64_t di = ai - bi;
			borrow = (ai < bi) | nb;
			rem[i] = di;
		}
		int i = 4;
		while (borrow && i <= 8) {
			uint64_t ai = rem[i];
			rem[i] = ai - borrow;
			borrow = (ai < borrow);
			i++;
		}
	}
	limbs_to_be(rem, out_be);
}

void os_secp256k1_scalar_mul(uint8_t *r, const uint8_t *a, const uint8_t *b)
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
	scalar_reduce(t, r);
}

void os_secp256k1_scalar_add(uint8_t *r, const uint8_t *a, const uint8_t *b)
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
	if (carry || fe_cmp_raw(s, N) >= 0)
		sub256(s, s, N);
	limbs_to_be(s, r);
}

int os_secp256k1_scalar_inv(uint8_t *r, const uint8_t *a)
{
	/* a^(n-2) mod n via square-and-multiply (reuses scalar_mul) */
	int nonzero = 0;
	for (int i = 0; i < 32; i++) if (a[i]) nonzero = 1;
	if (!nonzero) return -1;

	uint8_t res[32] = {0}, base[32];
	res[31] = 1;
	memcpy(base, a, 32);
	/* exponent n-2 */
	uint8_t e[32];
	static const uint8_t NBE[32] = {
		0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,
		0xBA,0xAE,0xDC,0xE6,0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,0x41,0x41 };
	/* e = n - 2 */
	int borrow = 0;
	for (int i = 31; i >= 0; i--) {
		int d = NBE[i] - (i == 31 ? 2 : 0) - borrow;
		if (d < 0) { d += 256; borrow = 1; } else borrow = 0;
		e[i] = (uint8_t)d;
	}
	for (int i = 0; i < 32; i++) {
		for (int b = 7; b >= 0; b--) {
			uint8_t t[32];
			os_secp256k1_scalar_mul(t, res, res);
			memcpy(res, t, 32);
			if ((e[i] >> b) & 1) {
				os_secp256k1_scalar_mul(t, res, base);
				memcpy(res, t, 32);
			}
		}
	}
	memcpy(r, res, 32);
	return 0;
}

/* ---- point parse/mul/add for ECDSA verify ---- */

int os_secp256k1_parse_pubkey(const uint8_t *pub33, void *point_out)
{
	point *p = (point *)point_out;
	if (pub33[0] != 0x02 && pub33[0] != 0x03)
		return -1;
	/* x */
	for (int i = 0; i < 4; i++) {
		uint64_t v = 0;
		for (int j = 0; j < 8; j++)
			v = (v << 8) | pub33[1 + (3 - i) * 8 + j];
		p->x.v[i] = v;
	}
	if (fe_cmp_raw(p->x.v, P) >= 0)
		return -1;
	/* y = sqrt(x^3 + 7); p ≡ 3 (mod 4) so sqrt = a^((p+1)/4) */
	fe x3, t;
	fe_sqr(&x3, &p->x);
	fe_mul(&x3, &x3, &p->x);
	fe seven = {{7,0,0,0}};
	fe_add(&x3, &x3, &seven);
	/* exponent (p+1)/4 */
	uint64_t e[4];
	{
		/* e = (p + 1) / 4 */
		uint64_t pe[4];
		uint64_t carry = 1;
		for (int i = 0; i < 4; i++) {
			u128 s = (u128)P[i] + (i == 0 ? 1 : 0) + 0;
			pe[i] = (uint64_t)s;
			carry = (uint64_t)(s >> 64);
			(void)carry;
		}
		/* pe might overflow; but p+1 < 2^256 since p = 2^256 - c */
		for (int i = 0; i < 4; i++)
			e[i] = (pe[i] >> 2) | (i < 3 ? pe[i + 1] << 62 : 0);
	}
	fe_zero(&t);
	t.v[0] = 1;
	fe base = x3, res = t;
	for (int i = 3; i >= 0; i--)
		for (int b = 63; b >= 0; b--) {
			fe_sqr(&res, &res);
			if ((e[i] >> b) & 1)
				fe_mul(&res, &res, &base);
		}
	/* verify res^2 == x3 */
	fe check;
	fe_sqr(&check, &res);
	if (fe_cmp_raw(check.v, x3.v) != 0)
		return -1;
	/* choose y with correct parity */
	int want_odd = pub33[0] == 0x03;
	if ((int)(res.v[0] & 1) != want_odd)
		fe_sub(&p->y, (const fe *)(&(fe){ .v = {P[0],P[1],P[2],P[3]} }), &res);
	else
		p->y = res;
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

int os_secp256k1_point_mul(const void *point_in, const uint8_t *k32, uint8_t *pub33)
{
	point r;
	pt_mul(&r, (const point *)point_in, k32);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_compressed(&r, pub33);
	return 0;
}

int os_secp256k1_point_add(const void *a, const void *b, uint8_t *pub33)
{
	point r;
	pt_add(&r, (const point *)a, (const point *)b);
	if (pt_is_infinity(&r))
		return -1;
	pt_serialize_compressed(&r, pub33);
	return 0;
}
