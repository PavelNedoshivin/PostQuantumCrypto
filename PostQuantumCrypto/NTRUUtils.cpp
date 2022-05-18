#define _CRT_SECURE_NO_WARNINGS
#include "NTRUUtils.hpp"

using namespace std;

namespace NTRU {

	void randombytes(vector<uint8_t>& x, uint64_t xlen)
	{
		uint32_t i;

		if (fd == -1) {
			for (;;) {
				if (fd != -1) break;
				chrono::milliseconds timespan(1);
				this_thread::sleep_for(timespan);
			}
		}

		while (xlen > 0) {
			if (xlen < 1048576) i = xlen; else i = 1048576;

			uint8_t* forRead = reinterpret_cast<uint8_t*>(&x[0]);
			if (i < 1) {
				chrono::milliseconds timespan(1);
				this_thread::sleep_for(timespan);
				continue;
			}

			vector<uint8_t> copy(x.begin() + i, x.end());
			x = copy;
			xlen -= i;
		}
	}

	static inline uint8_t mod3(uint8_t a) /* a between 0 and 9 */
	{
		int16_t t, c;
		a = (a >> 2) + (a & 3); /* between 0 and 4 */
		t = a - 3;
		c = t >> 5;
		return static_cast<uint8_t>(t ^ (c & (a ^ t)));
	}

	void sample_iid(poly& r, const vector<uint8_t>& uniformbytes)
	{
		uint32_t i;
		/* {0,1,...,255} -> {0,1,2}; Pr[0] = 86/256, Pr[1] = Pr[-1] = 85/256 */
		for (i = 0; i < NTRU_N - 1; i++)
			r.coeffs[i] = mod3(uniformbytes[i]);

		r.coeffs[NTRU_N - 1] = 0;
	}

	/* assume 2 <= n <= 0x40000000 */
	void crypto_sort_int32(vector<int32>& array, size_t n)
	{
		size_t top, p, q, r, i, j;
		vector<int32> x = array;

		top = 1;
		while (top < n - top) top += top;

		for (p = top; p >= 1; p >>= 1) {
			i = 0;
			while (i + 2 * p <= n) {
				for (j = i; j < i + p; ++j) {
					int32_MINMAX(x[j], x[j + p]);
				}
				i += 2 * p;
			}
			for (j = i; j < n - p; ++j) {
				int32_MINMAX(x[j], x[j + p]);
			}

			i = 0;
			j = 0;
			for (q = top; q > p; q >>= 1) {
				if (j != i) {
					for (;;) {
						if (j == n - q) goto done;
						int32 a = x[j + p];
						for (r = q; r > p; r >>= 1) {
							int32_MINMAX(a, x[j + r]);
						}
						x[j + p] = a;
						++j;
						if (j == i + p) {
							i += 2 * p;
							break;
						}
					}
				}
				while (i + p <= n - q) {
					for (j = i; j < i + p; ++j) {
						int32 a = x[j + p];
						for (r = q; r > p; r >>= 1) {
							int32_MINMAX(a, x[j + r]);
						}
						x[j + p] = a;
					}
					i += 2 * p;
				}
				/* now i + p > n - q */
				j = i;
				while (j < n - q) {
					int32 a = x[j + p];
					for (r = q; r > p; r >>= 1) {
						int32_MINMAX(a, x[j + r]);
					}
					x[j + p] = a;
					++j;
				}

			done:;
			}
		}
	}

	void sample_fixed_type(poly& r, const vector<uint8_t>& u)
	{
		// Assumes NTRU_SAMPLE_FT_BYTES = ceil(30*(n-1)/8)

		vector<int32_t> s(NTRU_N - 1);
		uint32_t i;

		// Use 30 bits of u per word
		for (i = 0; i < (NTRU_N - 1) / 4; i++)
		{
			s[4 * i + 0] = (u[15 * i + 0] << 2) + (u[15 * i + 1] << 10) + (u[15 * i + 2] << 18) + ((uint32_t)u[15 * i + 3] << 26);
			s[4 * i + 1] = ((u[15 * i + 3] & 0xc0) >> 4) + (u[15 * i + 4] << 4) + (u[15 * i + 5] << 12) + (u[15 * i + 6] << 20) + ((uint32_t)u[15 * i + 7] << 28);
			s[4 * i + 2] = ((u[15 * i + 7] & 0xf0) >> 2) + (u[15 * i + 8] << 6) + (u[15 * i + 9] << 14) + (u[15 * i + 10] << 22) + ((uint32_t)u[15 * i + 11] << 30);
			s[4 * i + 3] = (u[15 * i + 11] & 0xfc) + (u[15 * i + 12] << 8) + (u[15 * i + 13] << 16) + ((uint32_t)u[15 * i + 14] << 24);
		}
#if (NTRU_N - 1) > ((NTRU_N - 1) / 4) * 4 // (N-1) = 2 mod 4
		i = (NTRU_N - 1) / 4;
		s[4 * i + 0] = (u[15 * i + 0] << 2) + (u[15 * i + 1] << 10) + (u[15 * i + 2] << 18) + ((uint32_t)u[15 * i + 3] << 26);
		s[4 * i + 1] = ((u[15 * i + 3] & 0xc0) >> 4) + (u[15 * i + 4] << 4) + (u[15 * i + 5] << 12) + (u[15 * i + 6] << 20) + ((uint32_t)u[15 * i + 7] << 28);
#endif

		for (i = 0; i < NTRU_WEIGHT / 2; i++) s[i] |= 1;

		for (i = NTRU_WEIGHT / 2; i < NTRU_WEIGHT; i++) s[i] |= 2;

		crypto_sort_int32(s, NTRU_N - 1);

		for (i = 0; i < NTRU_N - 1; i++)
			r.coeffs[i] = ((uint16_t)(s[i] & 3));

		r.coeffs[NTRU_N - 1] = 0;
	}

	void sample_fg(poly& f, poly& g, vector<uint8_t>& uniformbytes)
	{
		sample_iid(f, uniformbytes);
		vector<uint8_t> copy(uniformbytes.begin() + NTRU_SAMPLE_IID_BYTES, uniformbytes.end());
		sample_fixed_type(g, copy);
		uniformbytes.insert(uniformbytes.begin() + NTRU_SAMPLE_IID_BYTES, copy.begin(), copy.end());
		uniformbytes.resize(NTRU_SAMPLE_IID_BYTES + copy.size());
	}

	static inline int16_t both_negative_mask(int16_t x, int16_t y)
	{
		return (x & y) >> 15;
	}

	void poly_S3_inv(poly& r, const poly& a)
	{
		poly f, g, v, w;
		f.coeffs.resize(NTRU_N);
		g.coeffs.resize(NTRU_N);
		v.coeffs.resize(NTRU_N);
		w.coeffs.resize(NTRU_N);
		size_t i, loop;
		int16_t delta, sign, swap, t;

		for (i = 0; i < NTRU_N; ++i) v.coeffs[i] = 0;
		for (i = 0; i < NTRU_N; ++i) w.coeffs[i] = 0;
		w.coeffs[0] = 1;

		for (i = 0; i < NTRU_N; ++i) f.coeffs[i] = 1;
		for (i = 0; i < NTRU_N - 1; ++i) g.coeffs[NTRU_N - 2 - i] = mod3((a.coeffs[i] & 3) + 2 * (a.coeffs[NTRU_N - 1] & 3));
		g.coeffs[NTRU_N - 1] = 0;

		delta = 1;

		for (loop = 0; loop < 2 * (NTRU_N - 1) - 1; ++loop) {
			for (i = NTRU_N - 1; i > 0; --i) v.coeffs[i] = v.coeffs[i - 1];
			v.coeffs[0] = 0;

			sign = mod3(static_cast<uint8_t>(2 * g.coeffs[0] * f.coeffs[0]));
			swap = both_negative_mask(-delta, -static_cast<int16_t>(g.coeffs[0]));
			delta ^= swap & (delta ^ -delta);
			delta += 1;

			for (i = 0; i < NTRU_N; ++i) {
				t = swap & (f.coeffs[i] ^ g.coeffs[i]); f.coeffs[i] ^= t; g.coeffs[i] ^= t;
				t = swap & (v.coeffs[i] ^ w.coeffs[i]); v.coeffs[i] ^= t; w.coeffs[i] ^= t;
			}

			for (i = 0; i < NTRU_N; ++i) g.coeffs[i] = mod3(static_cast<uint8_t>(g.coeffs[i] + sign * f.coeffs[i]));
			for (i = 0; i < NTRU_N; ++i) w.coeffs[i] = mod3(static_cast<uint8_t>(w.coeffs[i] + sign * v.coeffs[i]));
			for (i = 0; i < NTRU_N - 1; ++i) g.coeffs[i] = g.coeffs[i + 1];
			g.coeffs[NTRU_N - 1] = 0;
		}

		sign = f.coeffs[0];
		for (i = 0; i < NTRU_N - 1; ++i) r.coeffs[i] = mod3(static_cast<uint8_t>(sign * v.coeffs[NTRU_N - 2 - i]));
		r.coeffs[NTRU_N - 1] = 0;
	}

	void poly_S3_tobytes(vector<uint8_t>& msg, const poly& a)
	{
		uint32_t i;
		uint8_t c;
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
		uint32_t j;
#endif

		for (i = 0; i < NTRU_PACK_DEG / 5; i++)
		{
			c = a.coeffs[5 * i + 4] & 255;
			c = (3 * c + a.coeffs[5 * i + 3]) & 255;
			c = (3 * c + a.coeffs[5 * i + 2]) & 255;
			c = (3 * c + a.coeffs[5 * i + 1]) & 255;
			c = (3 * c + a.coeffs[5 * i + 0]) & 255;
			msg[i] = c;
		}
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
		i = NTRU_PACK_DEG / 5;
		c = 0;
		for (j = NTRU_PACK_DEG - (5 * i) - 1; j >= 0; j--)
			c = (3 * c + a.coeffs[5 * i + j]) & 255;
		msg[i] = c;
#endif
	}

	/* Map {0, 1, 2} -> {0,1,q-1} in place */
	void poly_Z3_to_Zq(poly& r)
	{
		uint32_t i;
		for (i = 0; i < NTRU_N; i++)
			r.coeffs[i] = r.coeffs[i] | ((-(r.coeffs[i] >> 1)) & (NTRU_Q - 1));
	}

	void poly_Rq_mul(poly& r, const poly& a, const poly& b)
	{
		uint32_t k, i;

		for (k = 0; k < NTRU_N; k++)
		{
			r.coeffs[k] = 0;
			for (i = 1; i < NTRU_N - k; i++)
				r.coeffs[k] += a.coeffs[k + i] * b.coeffs[NTRU_N - i];
			for (i = 0; i < k + 1; i++)
				r.coeffs[k] += a.coeffs[k - i] * b.coeffs[i];
		}
	}

	void poly_R2_inv(poly& r, const poly& a)
	{
		poly f, g, v, w;
		size_t i, loop;
		int16_t delta, sign, swap, t;

		for (i = 0; i < NTRU_N; ++i) v.coeffs[i] = 0;
		for (i = 0; i < NTRU_N; ++i) w.coeffs[i] = 0;
		w.coeffs[0] = 1;

		for (i = 0; i < NTRU_N; ++i) f.coeffs[i] = 1;
		for (i = 0; i < NTRU_N - 1; ++i) g.coeffs[NTRU_N - 2 - i] = (a.coeffs[i] ^ a.coeffs[NTRU_N - 1]) & 1;
		g.coeffs[NTRU_N - 1] = 0;

		delta = 1;

		for (loop = 0; loop < 2 * (NTRU_N - 1) - 1; ++loop) {
			for (i = NTRU_N - 1; i > 0; --i) v.coeffs[i] = v.coeffs[i - 1];
			v.coeffs[0] = 0;

			sign = g.coeffs[0] & f.coeffs[0];
			swap = both_negative_mask(-delta, -(int16_t)g.coeffs[0]);
			delta ^= swap & (delta ^ -delta);
			delta += 1;

			for (i = 0; i < NTRU_N; ++i) {
				t = swap & (f.coeffs[i] ^ g.coeffs[i]); f.coeffs[i] ^= t; g.coeffs[i] ^= t;
				t = swap & (v.coeffs[i] ^ w.coeffs[i]); v.coeffs[i] ^= t; w.coeffs[i] ^= t;
			}

			for (i = 0; i < NTRU_N; ++i) g.coeffs[i] = g.coeffs[i] ^ (sign & f.coeffs[i]);
			for (i = 0; i < NTRU_N; ++i) w.coeffs[i] = w.coeffs[i] ^ (sign & v.coeffs[i]);
			for (i = 0; i < NTRU_N - 1; ++i) g.coeffs[i] = g.coeffs[i + 1];
			g.coeffs[NTRU_N - 1] = 0;
		}

		for (i = 0; i < NTRU_N - 1; ++i) r.coeffs[i] = v.coeffs[NTRU_N - 2 - i];
		r.coeffs[NTRU_N - 1] = 0;
	}

	static void poly_R2_inv_to_Rq_inv(poly& r, const poly& ai, const poly& a)
	{
#if NTRU_Q <= 256 || NTRU_Q >= 65536
#error "poly_R2_inv_to_Rq_inv in poly.c assumes 256 < q < 65536"
#endif

		int i;
		poly b, c;
		poly s;

		// for 0..4
		//    ai = ai * (2 - a*ai)  mod q
		for (i = 0; i < NTRU_N; i++)
			b.coeffs[i] = -(a.coeffs[i]);

		for (i = 0; i < NTRU_N; i++)
			r.coeffs[i] = ai.coeffs[i];

		poly_Rq_mul(c, r, b);
		c.coeffs[0] += 2; // c = 2 - a*ai
		poly_Rq_mul(s, c, r); // s = ai*c

		poly_Rq_mul(c, s, b);
		c.coeffs[0] += 2; // c = 2 - a*s
		poly_Rq_mul(r, c, s); // r = s*c

		poly_Rq_mul(c, r, b);
		c.coeffs[0] += 2; // c = 2 - a*r
		poly_Rq_mul(s, c, r); // s = r*c

		poly_Rq_mul(c, s, b);
		c.coeffs[0] += 2; // c = 2 - a*s
		poly_Rq_mul(r, c, s); // r = s*c
	}

	void poly_Rq_inv(poly& r, const poly& a)
	{
		poly ai2;
		poly_R2_inv(ai2, a);
		poly_R2_inv_to_Rq_inv(r, ai2, a);
	}

	void poly_mod_q_Phi_n(poly& r)
	{
		int i;
		for (i = 0; i < NTRU_N; i++)
			r.coeffs[i] = r.coeffs[i] - r.coeffs[NTRU_N - 1];
	}

	void poly_Sq_mul(poly& r, const poly& a, const poly& b)
	{
		poly_Rq_mul(r, a, b);
		poly_mod_q_Phi_n(r);
	}

	void poly_Sq_tobytes(vector<uint8_t>& r, const poly& a)
	{
		uint32_t i, j;
		vector<uint16_t> t(8);

		for (i = 0; i < NTRU_PACK_DEG / 8; i++)
		{
			for (j = 0; j < 8; j++)
				t[j] = MODQ(a.coeffs[8 * i + j]);

			r[11 * i + 0] = static_cast<uint8_t>(t[0] & 0xff);
			r[11 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | ((t[1] & 0x1f) << 3));
			r[11 * i + 2] = static_cast<uint8_t>((t[1] >> 5) | ((t[2] & 0x03) << 6));
			r[11 * i + 3] = static_cast<uint8_t>((t[2] >> 2) & 0xff);
			r[11 * i + 4] = static_cast<uint8_t>((t[2] >> 10) | ((t[3] & 0x7f) << 1));
			r[11 * i + 5] = static_cast<uint8_t>((t[3] >> 7) | ((t[4] & 0x0f) << 4));
			r[11 * i + 6] = static_cast<uint8_t>((t[4] >> 4) | ((t[5] & 0x01) << 7));
			r[11 * i + 7] = static_cast<uint8_t>((t[5] >> 1) & 0xff);
			r[11 * i + 8] = static_cast<uint8_t>((t[5] >> 9) | ((t[6] & 0x3f) << 2));
			r[11 * i + 9] = static_cast<uint8_t>((t[6] >> 6) | ((t[7] & 0x07) << 5));
			r[11 * i + 10] = static_cast<uint8_t>((t[7] >> 3));
		}

		for (j = 0; j < NTRU_PACK_DEG - 8 * i; j++)
			t[j] = MODQ(a.coeffs[8 * i + j]);
		for (; j < 8; j++)
			t[j] = 0;

		switch (NTRU_PACK_DEG & 0x07)
		{
			// cases 0 and 6 are impossible since 2 generates (Z/n)* and
			// p mod 8 in {1, 7} implies that 2 is a quadratic residue.
		case 4:
			r[11 * i + 0] = static_cast<uint8_t>(t[0] & 0xff);
			r[11 * i + 1] = static_cast<uint8_t>(t[0] >> 8) | ((t[1] & 0x1f) << 3);
			r[11 * i + 2] = static_cast<uint8_t>(t[1] >> 5) | ((t[2] & 0x03) << 6);
			r[11 * i + 3] = static_cast<uint8_t>(t[2] >> 2) & 0xff;
			r[11 * i + 4] = static_cast<uint8_t>(t[2] >> 10) | ((t[3] & 0x7f) << 1);
			r[11 * i + 5] = static_cast<uint8_t>(t[3] >> 7) | ((t[4] & 0x0f) << 4);
			break;
		case 2:
			r[11 * i + 0] = static_cast<uint8_t>(t[0] & 0xff);
			r[11 * i + 1] = static_cast<uint8_t>(t[0] >> 8) | ((t[1] & 0x1f) << 3);
			r[11 * i + 2] = static_cast<uint8_t>(t[1] >> 5) | ((t[2] & 0x03) << 6);
			break;
		}
	}

	void poly_Rq_sum_zero_tobytes(vector<uint8_t>& r, const poly& a)
	{
		poly_Sq_tobytes(r, a);
	}

	void sample_rm(poly& r, poly& m, const vector<uint8_t>& uniformbytes)
	{
#ifdef NTRU_HRSS
		sample_iid(r, uniformbytes);
		sample_iid(m, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif

#ifdef NTRU_HPS
		sample_iid(r, uniformbytes);
		sample_fixed_type(m, uniformbytes + NTRU_SAMPLE_IID_BYTES);
#endif
	}

	void poly_Sq_frombytes(poly& r, const vector<uint8_t>& a)
	{
		int i;
		for (i = 0; i < NTRU_PACK_DEG / 8; i++)
		{
			r.coeffs[8 * i + 0] = (a[11 * i + 0] >> 0) | ((static_cast<uint16_t>(a[11 * i + 1]) & 0x07) << 8);
			r.coeffs[8 * i + 1] = (a[11 * i + 1] >> 3) | ((static_cast<uint16_t>(a[11 * i + 2]) & 0x3f) << 5);
			r.coeffs[8 * i + 2] = (a[11 * i + 2] >> 6) | ((static_cast<uint16_t>(a[11 * i + 3]) & 0xff) << 2) | ((static_cast<uint16_t>(a[11 * i + 4]) & 0x01) << 10);
			r.coeffs[8 * i + 3] = (a[11 * i + 4] >> 1) | ((static_cast<uint16_t>(a[11 * i + 5]) & 0x0f) << 7);
			r.coeffs[8 * i + 4] = (a[11 * i + 5] >> 4) | ((static_cast<uint16_t>(a[11 * i + 6]) & 0x7f) << 4);
			r.coeffs[8 * i + 5] = (a[11 * i + 6] >> 7) | ((static_cast<uint16_t>(a[11 * i + 7]) & 0xff) << 1) | ((static_cast<uint16_t>(a[11 * i + 8]) & 0x03) << 9);
			r.coeffs[8 * i + 6] = (a[11 * i + 8] >> 2) | ((static_cast<uint16_t>(a[11 * i + 9]) & 0x1f) << 6);
			r.coeffs[8 * i + 7] = (a[11 * i + 9] >> 5) | ((static_cast<uint16_t>(a[11 * i + 10]) & 0xff) << 3);
		}
		switch (NTRU_PACK_DEG & 0x07)
		{
			// cases 0 and 6 are impossible since 2 generates (Z/n)* and
			// p mod 8 in {1, 7} implies that 2 is a quadratic residue.
		case 4:
			r.coeffs[8 * i + 0] = (a[11 * i + 0] >> 0) | ((static_cast<uint16_t>(a[11 * i + 1]) & 0x07) << 8);
			r.coeffs[8 * i + 1] = (a[11 * i + 1] >> 3) | ((static_cast<uint16_t>(a[11 * i + 2]) & 0x3f) << 5);
			r.coeffs[8 * i + 2] = (a[11 * i + 2] >> 6) | ((static_cast<uint16_t>(a[11 * i + 3]) & 0xff) << 2) | ((static_cast<uint16_t>(a[11 * i + 4]) & 0x01) << 10);
			r.coeffs[8 * i + 3] = (a[11 * i + 4] >> 1) | ((static_cast<uint16_t>(a[11 * i + 5]) & 0x0f) << 7);
			break;
		case 2:
			r.coeffs[8 * i + 0] = (a[11 * i + 0] >> 0) | ((static_cast<uint16_t>(a[11 * i + 1]) & 0x07) << 8);
			r.coeffs[8 * i + 1] = (a[11 * i + 1] >> 3) | ((static_cast<uint16_t>(a[11 * i + 2]) & 0x3f) << 5);
			break;
		}
		r.coeffs[NTRU_N - 1] = 0;
	}

	void poly_Rq_sum_zero_frombytes(poly& r, const vector<uint8_t>& a)
	{
		uint32_t i;
		poly_Sq_frombytes(r, a);

		/* Set r[n-1] so that the sum of coefficients is zero mod q */
		r.coeffs[NTRU_N - 1] = 0;
		for (i = 0; i < NTRU_PACK_DEG; i++)
			r.coeffs[NTRU_N - 1] -= r.coeffs[i];
	}

	void poly_lift(poly& r, const poly& a)
	{
		uint32_t i;
		for (i = 0; i < NTRU_N; i++) {
			r.coeffs[i] = a.coeffs[i];
		}
		poly_Z3_to_Zq(r);
	}

	/*************************************************
	* Name:        load64
	*
	* Description: Load 8 bytes into uint64_t in little-endian order
	*
	* Arguments:   - const unsigned char *x: pointer to input byte array
	*
	* Returns the loaded 64-bit unsigned integer
	**************************************************/
	static uint64_t load64(const vector<uint8_t>& x)
	{
		uint64_t r = 0, i;

		for (i = 0; i < 8; ++i) {
			r |= static_cast<uint64_t>(x[i]) << 8 * i;
		}
		return r;
	}

	/* Keccak round constants */
	static const uint64_t KeccakF_RoundConstants[NROUNDS] =
	{
		(uint64_t)0x0000000000000001ULL,
		(uint64_t)0x0000000000008082ULL,
		(uint64_t)0x800000000000808aULL,
		(uint64_t)0x8000000080008000ULL,
		(uint64_t)0x000000000000808bULL,
		(uint64_t)0x0000000080000001ULL,
		(uint64_t)0x8000000080008081ULL,
		(uint64_t)0x8000000000008009ULL,
		(uint64_t)0x000000000000008aULL,
		(uint64_t)0x0000000000000088ULL,
		(uint64_t)0x0000000080008009ULL,
		(uint64_t)0x000000008000000aULL,
		(uint64_t)0x000000008000808bULL,
		(uint64_t)0x800000000000008bULL,
		(uint64_t)0x8000000000008089ULL,
		(uint64_t)0x8000000000008003ULL,
		(uint64_t)0x8000000000008002ULL,
		(uint64_t)0x8000000000000080ULL,
		(uint64_t)0x000000000000800aULL,
		(uint64_t)0x800000008000000aULL,
		(uint64_t)0x8000000080008081ULL,
		(uint64_t)0x8000000000008080ULL,
		(uint64_t)0x0000000080000001ULL,
		(uint64_t)0x8000000080008008ULL
	};

	/*************************************************
	* Name:        KeccakF1600_StatePermute
	*
	* Description: The Keccak F1600 Permutation
	*
	* Arguments:   - uint64_t * state: pointer to in/output Keccak state
	**************************************************/
	void KeccakF1600_StatePermute(vector<uint64_t>& state)
	{
		uint32_t round;

		uint64_t Aba, Abe, Abi, Abo, Abu;
		uint64_t Aga, Age, Agi, Ago, Agu;
		uint64_t Aka, Ake, Aki, Ako, Aku;
		uint64_t Ama, Ame, Ami, Amo, Amu;
		uint64_t Asa, Ase, Asi, Aso, Asu;
		uint64_t BCa, BCe, BCi, BCo, BCu;
		uint64_t Da, De, Di, Do, Du;
		uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
		uint64_t Ega, Ege, Egi, Ego, Egu;
		uint64_t Eka, Eke, Eki, Eko, Eku;
		uint64_t Ema, Eme, Emi, Emo, Emu;
		uint64_t Esa, Ese, Esi, Eso, Esu;

		//copyFromState(A, state)
		Aba = state[0];
		Abe = state[1];
		Abi = state[2];
		Abo = state[3];
		Abu = state[4];
		Aga = state[5];
		Age = state[6];
		Agi = state[7];
		Ago = state[8];
		Agu = state[9];
		Aka = state[10];
		Ake = state[11];
		Aki = state[12];
		Ako = state[13];
		Aku = state[14];
		Ama = state[15];
		Ame = state[16];
		Ami = state[17];
		Amo = state[18];
		Amu = state[19];
		Asa = state[20];
		Ase = state[21];
		Asi = state[22];
		Aso = state[23];
		Asu = state[24];

		for (round = 0; round < NROUNDS; round += 2)
		{
			//    prepareTheta
			BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
			BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
			BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
			BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
			BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

			//thetaRhoPiChiIotaPrepareTheta(round  , A, E)
			Da = BCu ^ ROL(BCe, 1);
			De = BCa ^ ROL(BCi, 1);
			Di = BCe ^ ROL(BCo, 1);
			Do = BCi ^ ROL(BCu, 1);
			Du = BCo ^ ROL(BCa, 1);

			Aba ^= Da;
			BCa = Aba;
			Age ^= De;
			BCe = ROL(Age, 44);
			Aki ^= Di;
			BCi = ROL(Aki, 43);
			Amo ^= Do;
			BCo = ROL(Amo, 21);
			Asu ^= Du;
			BCu = ROL(Asu, 14);
			Eba = BCa ^ ((~BCe) & BCi);
			Eba ^= static_cast<uint64_t>(KeccakF_RoundConstants[round]);
			Ebe = BCe ^ ((~BCi) & BCo);
			Ebi = BCi ^ ((~BCo) & BCu);
			Ebo = BCo ^ ((~BCu) & BCa);
			Ebu = BCu ^ ((~BCa) & BCe);

			Abo ^= Do;
			BCa = ROL(Abo, 28);
			Agu ^= Du;
			BCe = ROL(Agu, 20);
			Aka ^= Da;
			BCi = ROL(Aka, 3);
			Ame ^= De;
			BCo = ROL(Ame, 45);
			Asi ^= Di;
			BCu = ROL(Asi, 61);
			Ega = BCa ^ ((~BCe) & BCi);
			Ege = BCe ^ ((~BCi) & BCo);
			Egi = BCi ^ ((~BCo) & BCu);
			Ego = BCo ^ ((~BCu) & BCa);
			Egu = BCu ^ ((~BCa) & BCe);

			Abe ^= De;
			BCa = ROL(Abe, 1);
			Agi ^= Di;
			BCe = ROL(Agi, 6);
			Ako ^= Do;
			BCi = ROL(Ako, 25);
			Amu ^= Du;
			BCo = ROL(Amu, 8);
			Asa ^= Da;
			BCu = ROL(Asa, 18);
			Eka = BCa ^ ((~BCe) & BCi);
			Eke = BCe ^ ((~BCi) & BCo);
			Eki = BCi ^ ((~BCo) & BCu);
			Eko = BCo ^ ((~BCu) & BCa);
			Eku = BCu ^ ((~BCa) & BCe);

			Abu ^= Du;
			BCa = ROL(Abu, 27);
			Aga ^= Da;
			BCe = ROL(Aga, 36);
			Ake ^= De;
			BCi = ROL(Ake, 10);
			Ami ^= Di;
			BCo = ROL(Ami, 15);
			Aso ^= Do;
			BCu = ROL(Aso, 56);
			Ema = BCa ^ ((~BCe) & BCi);
			Eme = BCe ^ ((~BCi) & BCo);
			Emi = BCi ^ ((~BCo) & BCu);
			Emo = BCo ^ ((~BCu) & BCa);
			Emu = BCu ^ ((~BCa) & BCe);

			Abi ^= Di;
			BCa = ROL(Abi, 62);
			Ago ^= Do;
			BCe = ROL(Ago, 55);
			Aku ^= Du;
			BCi = ROL(Aku, 39);
			Ama ^= Da;
			BCo = ROL(Ama, 41);
			Ase ^= De;
			BCu = ROL(Ase, 2);
			Esa = BCa ^ ((~BCe) & BCi);
			Ese = BCe ^ ((~BCi) & BCo);
			Esi = BCi ^ ((~BCo) & BCu);
			Eso = BCo ^ ((~BCu) & BCa);
			Esu = BCu ^ ((~BCa) & BCe);

			//    prepareTheta
			BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
			BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
			BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
			BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
			BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

			//thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
			Da = BCu ^ ROL(BCe, 1);
			De = BCa ^ ROL(BCi, 1);
			Di = BCe ^ ROL(BCo, 1);
			Do = BCi ^ ROL(BCu, 1);
			Du = BCo ^ ROL(BCa, 1);

			Eba ^= Da;
			BCa = Eba;
			Ege ^= De;
			BCe = ROL(Ege, 44);
			Eki ^= Di;
			BCi = ROL(Eki, 43);
			Emo ^= Do;
			BCo = ROL(Emo, 21);
			Esu ^= Du;
			BCu = ROL(Esu, 14);
			Aba = BCa ^ ((~BCe) & BCi);
			Aba ^= static_cast<uint64_t>(KeccakF_RoundConstants[round + 1]);
			Abe = BCe ^ ((~BCi) & BCo);
			Abi = BCi ^ ((~BCo) & BCu);
			Abo = BCo ^ ((~BCu) & BCa);
			Abu = BCu ^ ((~BCa) & BCe);

			Ebo ^= Do;
			BCa = ROL(Ebo, 28);
			Egu ^= Du;
			BCe = ROL(Egu, 20);
			Eka ^= Da;
			BCi = ROL(Eka, 3);
			Eme ^= De;
			BCo = ROL(Eme, 45);
			Esi ^= Di;
			BCu = ROL(Esi, 61);
			Aga = BCa ^ ((~BCe) & BCi);
			Age = BCe ^ ((~BCi) & BCo);
			Agi = BCi ^ ((~BCo) & BCu);
			Ago = BCo ^ ((~BCu) & BCa);
			Agu = BCu ^ ((~BCa) & BCe);

			Ebe ^= De;
			BCa = ROL(Ebe, 1);
			Egi ^= Di;
			BCe = ROL(Egi, 6);
			Eko ^= Do;
			BCi = ROL(Eko, 25);
			Emu ^= Du;
			BCo = ROL(Emu, 8);
			Esa ^= Da;
			BCu = ROL(Esa, 18);
			Aka = BCa ^ ((~BCe) & BCi);
			Ake = BCe ^ ((~BCi) & BCo);
			Aki = BCi ^ ((~BCo) & BCu);
			Ako = BCo ^ ((~BCu) & BCa);
			Aku = BCu ^ ((~BCa) & BCe);

			Ebu ^= Du;
			BCa = ROL(Ebu, 27);
			Ega ^= Da;
			BCe = ROL(Ega, 36);
			Eke ^= De;
			BCi = ROL(Eke, 10);
			Emi ^= Di;
			BCo = ROL(Emi, 15);
			Eso ^= Do;
			BCu = ROL(Eso, 56);
			Ama = BCa ^ ((~BCe) & BCi);
			Ame = BCe ^ ((~BCi) & BCo);
			Ami = BCi ^ ((~BCo) & BCu);
			Amo = BCo ^ ((~BCu) & BCa);
			Amu = BCu ^ ((~BCa) & BCe);

			Ebi ^= Di;
			BCa = ROL(Ebi, 62);
			Ego ^= Do;
			BCe = ROL(Ego, 55);
			Eku ^= Du;
			BCi = ROL(Eku, 39);
			Ema ^= Da;
			BCo = ROL(Ema, 41);
			Ese ^= De;
			BCu = ROL(Ese, 2);
			Asa = BCa ^ ((~BCe) & BCi);
			Ase = BCe ^ ((~BCi) & BCo);
			Asi = BCi ^ ((~BCo) & BCu);
			Aso = BCo ^ ((~BCu) & BCa);
			Asu = BCu ^ ((~BCa) & BCe);
		}

		//copyToState(state, A)
		state[0] = Aba;
		state[1] = Abe;
		state[2] = Abi;
		state[3] = Abo;
		state[4] = Abu;
		state[5] = Aga;
		state[6] = Age;
		state[7] = Agi;
		state[8] = Ago;
		state[9] = Agu;
		state[10] = Aka;
		state[11] = Ake;
		state[12] = Aki;
		state[13] = Ako;
		state[14] = Aku;
		state[15] = Ama;
		state[16] = Ame;
		state[17] = Ami;
		state[18] = Amo;
		state[19] = Amu;
		state[20] = Asa;
		state[21] = Ase;
		state[22] = Asi;
		state[23] = Aso;
		state[24] = Asu;

#undef    round
	}

	/*************************************************
	* Name:        keccak_absorb
	*
	* Description: Absorb step of Keccak;
	*              non-incremental, starts by zeroeing the state.
	*
	* Arguments:   - uint64_t *s:             pointer to (uninitialized) output Keccak state
	*              - unsigned int r:          rate in bytes (e.g., 168 for SHAKE128)
	*              - const unsigned char *m:  pointer to input to be absorbed into s
	*              - unsigned long long mlen: length of input in bytes
	*              - unsigned char p:         domain-separation byte for different Keccak-derived functions
	**************************************************/
	static void keccak_absorb(vector<uint64_t>& s,
		uint32_t r,
		vector<uint8_t>& m, uint64_t mlen,
		uint8_t p)
	{
		uint64_t i;
		vector<uint8_t> t(200);

		// Zero state
		for (i = 0; i < 25; ++i)
			s[i] = 0;

		while (mlen >= r)
		{
			for (i = 0; i < r / 8; ++i) {
				vector<uint8_t> copy(m.begin() + 8 * i, m.end());
				s[i] ^= load64(copy);
				m.insert(m.begin() + 8 * i, copy.begin(), copy.end());
				m.resize(8 * i + copy.size());
			}

			KeccakF1600_StatePermute(s);
			mlen -= r;
			vector<uint8_t> copy(m.begin() + r, m.end());
			m = copy;
		}

		for (i = 0; i < r; ++i)
			t[i] = 0;
		for (i = 0; i < mlen; ++i)
			t[i] = m[i];
		t[i] = p;
		t[r - 1] |= 128;
		for (i = 0; i < r / 8; ++i) {
			vector<uint8_t> copy(m.begin() + 8 * i, m.end());
			s[i] ^= load64(copy);
			t.insert(t.begin() + 8 * i, copy.begin(), copy.end());
			t.resize(8 * i + copy.size());
		}
	}

	/*************************************************
	* Name:        store64
	*
	* Description: Store a 64-bit integer to a byte array in little-endian order
	*
	* Arguments:   - uint8_t *x: pointer to the output byte array
	*              - uint64_t u: input 64-bit unsigned integer
	**************************************************/
	static void store64(vector<uint8_t>& x, uint64_t u)
	{
		uint32_t i;

		for (i = 0; i < 8; ++i) {
			x[i] = u;
			u >>= 8;
		}
	}

	/*************************************************
	* Name:        keccak_squeezeblocks
	*
	* Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
	*              Modifies the state. Can be called multiple times to keep squeezing,
	*              i.e., is incremental.
	*
	* Arguments:   - unsigned char *h:               pointer to output blocks
	*              - unsigned long long int nblocks: number of blocks to be squeezed (written to h)
	*              - uint64_t *s:                    pointer to in/output Keccak state
	*              - unsigned int r:                 rate in bytes (e.g., 168 for SHAKE128)
	**************************************************/
	static void keccak_squeezeblocks(vector<uint8_t>& h, uint64_t nblocks,
		vector<uint64_t>& s,
		uint32_t r)
	{
		uint32_t i;
		while (nblocks > 0)
		{
			KeccakF1600_StatePermute(s);
			for (i = 0; i < (r >> 3); i++)
			{
				vector<uint8_t> copy(h.begin() + 8 * i, h.end());
				store64(copy, s[i]);
				h.insert(h.begin() + 8 * i, copy.begin(), copy.end());
				h.resize(8 * i + copy.size());
			}
			vector<uint8_t> copy(h.begin() + r, h.end());
			h = copy;
			nblocks--;
		}
	}

	/*************************************************
	* Name:        sha3_256
	*
	* Description: SHA3-256 with non-incremental API
	*
	* Arguments:   - unsigned char *output:      pointer to output
	*              - const unsigned char *input: pointer to input
	*              - unsigned long long inlen:   length of input in bytes
	**************************************************/
	void sha3_256(vector<uint8_t>& output, vector<uint8_t>& input, uint64_t inlen)
	{
		vector<uint64_t> s(25);
		vector<uint8_t> t(SHA3_256_RATE);
		size_t i;

		/* Absorb input */
		keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

		/* Squeeze output */
		keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

		for (i = 0; i < 32; i++)
			output[i] = t[i];
	}

	void poly_mod_3_Phi_n(poly& r)
	{
		uint32_t i;
		for (i = 0; i < NTRU_N; i++)
			r.coeffs[i] = mod3(r.coeffs[i] + 2 * r.coeffs[NTRU_N - 1]);
	}

	void poly_S3_frombytes(poly& r, const vector<uint8_t>& msg)
	{
		uint32_t i;
		uint8_t c;
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
		uint32_t j;
#endif

		for (i = 0; i < NTRU_PACK_DEG / 5; i++)
		{
			c = msg[i];
			r.coeffs[5 * i + 0] = c;
			r.coeffs[5 * i + 1] = c * 171 >> 9;  // this is division by 3
			r.coeffs[5 * i + 2] = c * 57 >> 9;  // division by 3^2
			r.coeffs[5 * i + 3] = c * 19 >> 9;  // division by 3^3
			r.coeffs[5 * i + 4] = c * 203 >> 14;  // etc.
		}
#if NTRU_PACK_DEG > (NTRU_PACK_DEG / 5) * 5  // if 5 does not divide NTRU_N-1
		i = NTRU_PACK_DEG / 5;
		c = msg[i];
		for (j = 0; (5 * i + j) < NTRU_PACK_DEG; j++)
		{
			r.coeffs[5 * i + j] = c;
			c = c * 171 >> 9;
		}
#endif
		r.coeffs[NTRU_N - 1] = 0;
		poly_mod_3_Phi_n(r);
	}

	void poly_Rq_to_S3(poly& r, const poly& a)
	{
		uint32_t i;
		uint16_t flag;

		/* The coefficients of a are stored as non-negative integers. */
		/* We must translate to representatives in [-q/2, q/2) before */
		/* reduction mod 3.                                           */
		for (i = 0; i < NTRU_N; i++)
		{
			/* Need an explicit reduction mod q here                    */
			r.coeffs[i] = MODQ(a.coeffs[i]);

			/* flag = 1 if r[i] >= q/2 else 0                            */
			flag = r.coeffs[i] >> (NTRU_LOGQ - 1);

			/* Now we will add (-q) mod 3 if r[i] >= q/2                 */
			/* Note (-q) mod 3=(-2^k) mod 3=1<<(1-(k&1))                */
			r.coeffs[i] += flag << (1 - (NTRU_LOGQ & 1));
		}

		poly_mod_3_Phi_n(r);
	}

	void poly_S3_mul(poly& r, const poly& a, const poly& b)
	{
		uint32_t i;

		/* Our S3 multiplications do not overflow mod q,    */
		/* so we can re-purpose poly_Rq_mul, as long as we  */
		/* follow with an explicit reduction mod q.         */
		poly_Rq_mul(r, a, b);
		for (i = 0; i < NTRU_N; i++) {
			r.coeffs[i] = MODQ(r.coeffs[i]);
		}
		poly_mod_3_Phi_n(r);
	}

	/* Map {0, 1, q-1} -> {0,1,2} in place */
	void poly_trinary_Zq_to_Z3(poly& r)
	{
		uint32_t i;
		for (i = 0; i < NTRU_N; i++)
		{
			r.coeffs[i] = MODQ(r.coeffs[i]);
			r.coeffs[i] = 3 & (r.coeffs[i] ^ (r.coeffs[i] >> (NTRU_LOGQ - 1)));
		}
	}

	/* b = 1 means mov, b = 0 means don't mov*/
	void cmov(vector<uint8_t>& r, const vector<uint8_t>& x, size_t len, uint8_t b)
	{
		size_t i;

		b = (~b + 1);
		for (i = 0; i < len; i++)
			r[i] ^= b & (x[i] ^ r[i]);
	}

}
