#include "ClassicMcElieceUtils.hpp"

using namespace std;

namespace ClassicMcEliece {

	uint16_t load_gf(const vector<uint8_t>& src)
	{
		uint16_t a;

		a = src[1];
		a <<= 8;
		a |= src[0];

		return a & GFMASK;
	}

	void randombytes(vector<uint8_t>& out, size_t outlen) {
		HCRYPTPROV ctx;
		size_t len;

		if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
			abort();

		while (outlen > 0) {
			len = (outlen > 1048576) ? 1048576 : outlen;
			if (!CryptGenRandom(ctx, len, (BYTE*)&out[0]))
				abort();

			vector<uint8_t> copy(out.begin() + len, out.end());
			out = copy;
			outlen -= len;
		}

		if (!CryptReleaseContext(ctx, 0))
			abort();
	}

	gf bitrev(gf a)
	{
		a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
		a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
		a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
		a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);

		return a >> 4;
	}

	uint64_t load8(const vector<uint8_t>& in)
	{
		int32_t i;
		uint64_t ret = in[7];

		for (i = 6; i >= 0; i--)
		{
			ret <<= 8;
			ret |= in[i];
		}

		return ret;
	}

	/* input: in, a 64x64 matrix over GF(2) */
	/* output: out, transpose of in */
	void transpose_64x64(vector<uint64_t>& out, vector<uint64_t>& in)
	{
		uint32_t i, j, s;
		int32_t d;

		uint64_t x, y;
		uint64_t masks[6][2] = {
								{0x5555555555555555, 0xAAAAAAAAAAAAAAAA},
								{0x3333333333333333, 0xCCCCCCCCCCCCCCCC},
								{0x0F0F0F0F0F0F0F0F, 0xF0F0F0F0F0F0F0F0},
								{0x00FF00FF00FF00FF, 0xFF00FF00FF00FF00},
								{0x0000FFFF0000FFFF, 0xFFFF0000FFFF0000},
								{0x00000000FFFFFFFF, 0xFFFFFFFF00000000}
		};

		for (i = 0; i < 64; i++)
			out[i] = in[i];

		for (d = 5; d >= 0; d--)
		{
			s = 1 << d;

			for (i = 0; i < 64; i += s * 2)
				for (j = i; j < i + s; j++)
				{
					x = (out[j] & masks[d][0]) | ((out[j + s] & masks[d][0]) << s);
					y = ((out[j] & masks[d][1]) >> s) | (out[j + s] & masks[d][1]);

					out[j + 0] = x;
					out[j + s] = y;
				}
		}
	}

	uint32_t load4(const vector<uint8_t>& in)
	{
		int32_t i;
		uint32_t ret = in[3];

		for (i = 2; i >= 0; i--)
		{
			ret <<= 8;
			ret |= in[i];
		}

		return ret;
	}

	/* one layer of the benes network */
	static void layer(vector<uint64_t>& data, vector<uint64_t>& bits, uint32_t lgs)
	{
		uint32_t i, j, s;

		uint64_t d;

		s = 1 << lgs;

		uint32_t bits_ptr = 0;

		for (i = 0; i < 64; i += s * 2)
			for (j = i; j < i + s; j++)
			{

				d = (data[j + 0] ^ data[j + s]);
				d &= bits[bits_ptr++];
				data[j + 0] ^= d;
				data[j + s] ^= d;
			}
	}

	void store8(vector<uint8_t>& out, uint64_t in)
	{
		out[0] = (in >> 0x00) & 0xFF;
		out[1] = (in >> 0x08) & 0xFF;
		out[2] = (in >> 0x10) & 0xFF;
		out[3] = (in >> 0x18) & 0xFF;
		out[4] = (in >> 0x20) & 0xFF;
		out[5] = (in >> 0x28) & 0xFF;
		out[6] = (in >> 0x30) & 0xFF;
		out[7] = (in >> 0x38) & 0xFF;
	}

	/* input: r, sequence of bits to be permuted */
	/*        bits, condition bits of the Benes network */
	/*        rev, 0 for normal application; !0 for inverse */
	/* output: r, permuted bits */
	void apply_benes(vector<uint8_t>& r, vector<uint8_t>& bits, uint32_t rev)
	{
		uint32_t i;

		uint64_t cond_ptr;
		uint32_t inc;
		int32_t low;

		vector<uint64_t> bs(64);
		vector<uint64_t> cond(64);

		//

		for (i = 0; i < 64; i++)
		{
			vector<uint8_t> copy(r.begin() + i * 8, r.end());
			bs[i] = ClassicMcEliece::load8(copy);
			r.insert(r.begin() + i * 8, copy.begin(), copy.end());
			r.resize(i * 8 + copy.size());
		}

		if (rev == 0)
		{
			inc = 256;
			cond_ptr = 0;
		}
		else
		{
			inc = -256;
			cond_ptr = (2 * GFBITS - 2) * 256;
		}

		//

		ClassicMcEliece::transpose_64x64(bs, bs);

		for (low = 0; low <= 5; low++)
		{
			for (i = 0; i < 64; i++) {
				vector<uint8_t> copy(bits.begin() + cond_ptr + i * 4, bits.end());
				cond[i] = ClassicMcEliece::load4(copy);
				bits.insert(bits.begin() + cond_ptr + i * 4, copy.begin(), copy.end());
				bits.resize(cond_ptr + i * 4 + copy.size());
			}
			ClassicMcEliece::transpose_64x64(cond, cond);
			layer(bs, cond, low);
			cond_ptr += inc;
		}

		ClassicMcEliece::transpose_64x64(bs, bs);

		for (low = 0; low <= 5; low++)
		{
			for (i = 0; i < 32; i++) {
				vector<uint8_t> copy(bits.begin() + cond_ptr + i * 8, bits.end());
				cond[i] = ClassicMcEliece::load8(copy);
				bits.insert(bits.begin() + cond_ptr + i * 8, copy.begin(), copy.end());
				bits.resize(cond_ptr + i * 8 + copy.size());
			}
			layer(bs, cond, low);
			cond_ptr += inc;
		}
		for (low = 4; low >= 0; low--)
		{
			for (i = 0; i < 32; i++) {
				vector<uint8_t> copy(bits.begin() + cond_ptr + i * 8, bits.end());
				cond[i] = ClassicMcEliece::load8(copy);
				bits.insert(bits.begin() + cond_ptr + i * 8, copy.begin(), copy.end());
				bits.resize(cond_ptr + i * 8 + copy.size());
			}
			layer(bs, cond, low);
			cond_ptr += inc;
		}

		ClassicMcEliece::transpose_64x64(bs, bs);

		for (low = 5; low >= 0; low--)
		{
			for (i = 0; i < 64; i++) {
				vector<uint8_t> copy(bits.begin() + cond_ptr + i * 4, bits.end());
				cond[i] = ClassicMcEliece::load4(copy);
				bits.insert(bits.begin() + cond_ptr + i * 4, copy.begin(), copy.end());
				bits.resize(cond_ptr + i * 4 + copy.size());
			}
			ClassicMcEliece::transpose_64x64(cond, cond);
			layer(bs, cond, low);
			cond_ptr += inc;
		}

		ClassicMcEliece::transpose_64x64(bs, bs);

		//

		for (i = 0; i < 64; i++)
		{
			vector<uint8_t> copy(r.begin() + i * 8, r.end());
			ClassicMcEliece::store8(copy, bs[i]);
			r.insert(r.begin() + i * 8, copy.begin(), copy.end());
			r.resize(i * 8 + copy.size());
		}
	}

	/* input: condition bits c */
	/* output: support s */
	void support_gen(vector<gf>& s, vector<uint8_t>& c)
	{
		gf a;
		uint32_t i;
		int32_t j;
		vector<vector<uint8_t>>  L(GFBITS);
		for (i = 0; i < GFBITS; i++) {
			L[i].resize((1 << GFBITS) / 8);
		}

		for (i = 0; i < GFBITS; i++)
			for (j = 0; j < (1 << GFBITS) / 8; j++)
				L[i][j] = 0;

		for (i = 0; i < (1 << GFBITS); i++)
		{
			a = ClassicMcEliece::bitrev((gf)i);

			for (j = 0; j < GFBITS; j++)
				L[j][i / 8] |= ((a >> j) & 1) << (i % 8);
		}

		for (j = 0; j < GFBITS; j++)
			ClassicMcEliece::apply_benes(L[j], c, 0);

		for (i = 0; i < SYS_N; i++)
		{
			s[i] = 0;
			for (j = GFBITS - 1; j >= 0; j--)
			{
				s[i] <<= 1;
				s[i] |= (L[j][i / 8] >> (i % 8)) & 1;
			}
		}
	}

	gf gf_mul(gf in0, gf in1)
	{
		uint32_t i;

		uint32_t tmp;
		uint32_t t0;
		uint32_t t1;
		uint32_t t;

		t0 = in0;
		t1 = in1;

		tmp = t0 * (t1 & 1);

		for (i = 1; i < GFBITS; i++)
			tmp ^= (t0 * (t1 & (1 << i)));

		t = tmp & 0x7FC000;
		tmp ^= t >> 9;
		tmp ^= t >> 12;

		t = tmp & 0x3000;
		tmp ^= t >> 9;
		tmp ^= t >> 12;

		return tmp & ((1 << GFBITS) - 1);
	}

	gf gf_add(gf in0, gf in1)
	{
		return in0 ^ in1;
	}

	/* input: polynomial f and field element a */
	/* return f(a) */
	gf eval(vector<gf>& f, gf a)
	{
		int32_t i;
		gf r;

		r = f[SYS_T];

		for (i = SYS_T - 1; i >= 0; i--)
		{
			r = ClassicMcEliece::gf_mul(r, a);
			r = ClassicMcEliece::gf_add(r, f[i]);
		}

		return r;
	}

	/* input: field element in */
	/* return: in^2 */
	static inline gf gf_sq(gf in)
	{
		const uint32_t B[] = { 0x55555555, 0x33333333, 0x0F0F0F0F, 0x00FF00FF };

		uint32_t x = in;
		uint32_t t;

		x = (x | (x << 8)) & B[3];
		x = (x | (x << 4)) & B[2];
		x = (x | (x << 2)) & B[1];
		x = (x | (x << 1)) & B[0];

		t = x & 0x7FC000;
		x ^= t >> 9;
		x ^= t >> 12;

		t = x & 0x3000;
		x ^= t >> 9;
		x ^= t >> 12;

		return x & ((1 << GFBITS) - 1);
	}

	gf gf_inv(gf in)
	{
		gf tmp_11;
		gf tmp_1111;

		gf out = in;

		out = gf_sq(out);
		tmp_11 = ClassicMcEliece::gf_mul(out, in); // 11

		out = gf_sq(tmp_11);
		out = gf_sq(out);
		tmp_1111 = ClassicMcEliece::gf_mul(out, tmp_11); // 1111

		out = gf_sq(tmp_1111);
		out = gf_sq(out);
		out = gf_sq(out);
		out = gf_sq(out);
		out = ClassicMcEliece::gf_mul(out, tmp_1111); // 11111111

		out = gf_sq(out);
		out = gf_sq(out);
		out = ClassicMcEliece::gf_mul(out, tmp_11); // 1111111111

		out = gf_sq(out);
		out = ClassicMcEliece::gf_mul(out, in); // 11111111111

		return gf_sq(out); // 111111111110
	}

	/* input: Goppa polynomial f, support L, received word r */
	/* output: out, the syndrome of length 2t */
	void synd(vector<gf>& out, vector<gf>& f, vector<gf>& L, vector<uint8_t>& r)
	{
		uint32_t i, j;
		gf e, e_inv, c;

		for (j = 0; j < 2 * SYS_T; j++)
			out[j] = 0;

		for (i = 0; i < SYS_N; i++)
		{
			c = (r[i / 8] >> (i % 8)) & 1;

			e = ClassicMcEliece::eval(f, L[i]);
			e_inv = ClassicMcEliece::gf_inv(ClassicMcEliece::gf_mul(e, e));

			for (j = 0; j < 2 * SYS_T; j++)
			{
				out[j] = ClassicMcEliece::gf_add(out[j], ClassicMcEliece::gf_mul(e_inv, c));
				e_inv = ClassicMcEliece::gf_mul(e_inv, L[i]);
			}
		}
	}

	/* input: field element den, num */
	/* return: (num/den) */
	gf gf_frac(gf den, gf num)
	{
		return ClassicMcEliece::gf_mul(ClassicMcEliece::gf_inv(den), num);
	}

	/* the Berlekamp-Massey algorithm */
	/* input: s, sequence of field elements */
	/* output: out, minimal polynomial of s */
	void bm(vector<gf>& out, vector<gf>& s)
	{
		uint32_t i;

		int32_t N = 0;
		uint16_t L = 0;
		uint16_t mle;
		uint16_t mne;

		vector<gf> T(SYS_T + 1);
		vector<gf> C(SYS_T + 1);
		vector<gf> B(SYS_T + 1);

		gf b = 1, d, f;

		//

		for (i = 0; i < SYS_T + 1; i++)
			C[i] = B[i] = 0;

		B[1] = C[0] = 1;

		//

		for (N = 0; N < 2 * SYS_T; N++)
		{
			d = 0;

			for (i = 0; i <= min(N, SYS_T); i++)
				d ^= ClassicMcEliece::gf_mul(C[i], s[N - i]);

			mne = d; mne -= 1;   mne >>= 15; mne -= 1;
			mle = N; mle -= 2 * L; mle >>= 15; mle -= 1;
			mle &= mne;

			for (i = 0; i <= SYS_T; i++)
				T[i] = C[i];

			f = ClassicMcEliece::gf_frac(b, d);

			for (i = 0; i <= SYS_T; i++)
				C[i] ^= ClassicMcEliece::gf_mul(f, B[i]) & mne;

			L = (L & ~mle) | ((N + 1 - L) & mle);

			for (i = 0; i <= SYS_T; i++)
				B[i] = (B[i] & ~mle) | (T[i] & mle);

			b = (b & ~mle) | (d & mle);

			for (i = SYS_T; i >= 1; i--) B[i] = B[i - 1];
			B[0] = 0;
		}

		for (i = 0; i <= SYS_T; i++)
			out[i] = C[SYS_T - i];
	}

	/* input: polynomial f and list of field elements L */
	/* output: out = [ f(a) for a in L ] */
	void root(vector<gf>& out, vector<gf>& f, vector<gf>& L)
	{
		uint32_t i;

		for (i = 0; i < SYS_N; i++)
			out[i] = ClassicMcEliece::eval(f, L[i]);
	}

	gf gf_iszero(gf a)
	{
		uint32_t t = a;

		t -= 1;
		t >>= 19;

		return (gf)t;
	}

	/* input: in0, in1 in GF((2^m)^t)*/
	/* output: out = in0*in1 */
	void GF_mul(vector<gf>& out, vector<gf>& in0, vector<gf>& in1)
	{
		uint32_t i, j;

		vector<gf> prod(SYS_T * 2 - 1);

		for (i = 0; i < SYS_T * 2 - 1; i++)
			prod[i] = 0;

		for (i = 0; i < SYS_T; i++)
			for (j = 0; j < SYS_T; j++)
				prod[i + j] ^= ClassicMcEliece::gf_mul(in0[i], in1[j]);

		//

		for (i = (SYS_T - 1) * 2; i >= SYS_T; i--)
		{
			prod[i - SYS_T + 3] ^= prod[i];
			prod[i - SYS_T + 1] ^= prod[i];
			prod[i - SYS_T + 0] ^= ClassicMcEliece::gf_mul(prod[i], (gf)2);
		}

		for (i = 0; i < SYS_T; i++)
			out[i] = prod[i];
	}

	/* input: f, element in GF((2^m)^t) */
	/* output: out, minimal polynomial of f */
	/* return: 0 for success and -1 for failure */
	uint32_t genpoly_gen(vector<gf>& out, vector<gf>& f)
	{
		uint32_t i, j, k, c;

		vector<vector<gf>> mat(SYS_T + 1);
		for (i = 0; i < SYS_T + 1; i++) {
			mat[i].resize(SYS_T);
		}
		gf mask, inv, t;

		// fill matrix

		mat[0][0] = 1;

		for (i = 1; i < SYS_T; i++)
			mat[0][i] = 0;

		for (i = 0; i < SYS_T; i++)
			mat[1][i] = f[i];

		for (j = 2; j <= SYS_T; j++)
			ClassicMcEliece::GF_mul(mat[j], mat[j - 1], f);

		// gaussian

		for (j = 0; j < SYS_T; j++)
		{
			for (k = j + 1; k < SYS_T; k++)
			{
				mask = ClassicMcEliece::gf_iszero(mat[j][j]);

				for (c = j; c < SYS_T + 1; c++)
					mat[c][j] ^= mat[c][k] & mask;

			}

			if (mat[j][j] == 0) // return if not systematic
			{
				return -1;
			}

			inv = ClassicMcEliece::gf_inv(mat[j][j]);

			for (c = j; c < SYS_T + 1; c++)
				mat[c][j] = ClassicMcEliece::gf_mul(mat[c][j], inv);

			for (k = 0; k < SYS_T; k++)
			{
				if (k != j)
				{
					t = mat[j][k];

					for (c = j; c < SYS_T + 1; c++)
						mat[c][k] ^= ClassicMcEliece::gf_mul(mat[c][j], t);
				}
			}
		}

		for (i = 0; i < SYS_T; i++)
			out[i] = mat[SYS_T][i];

		return 0;
	}

	void store_gf(vector<uint8_t>& dest, gf a)
	{
		dest[0] = a & 0xFF;
		dest[1] = a >> 8;
	}

	static void int32_sort(vector<int32_t>& x, uint64_t n)
	{
		uint64_t top, p, q, r, i;

		if (n < 2) return;
		top = 1;
		while (top < n - top) top += top;

		for (p = top; p > 0; p >>= 1) {
			for (i = 0; i < n - p; ++i)
				if (!(i & p))
					int32_MINMAX(x[i], x[i + p]);
			i = 0;
			for (q = top; q > p; q >>= 1) {
				for (; i < n - q; ++i) {
					if (!(i & p)) {
						int32_t a = x[i + p];
						for (r = q; r > p; r >>= 1)
							int32_MINMAX(a, x[i + r]);
						x[i + p] = a;
					}
				}
			}
		}
	}

	/* parameters: 1 <= w <= 14; n = 2^w */
	/* input: permutation pi of {0,1,...,n-1} */
	/* output: (2m-1)n/2 control bits at positions pos,pos+step,... */
	/* output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
	/* caller must 0-initialize positions first */
	/* temp must have space for int32[2*n] */
	static void cbrecursion(vector<uint8_t>& out, uint64_t pos, uint64_t step, const vector<int16>& pi, uint64_t w, uint64_t n, vector<int32> temp)
	{
#define A temp

		uint64_t x, i, j, k;
		vector<int32> copyB(temp.begin() + n, temp.end());
		vector<int16> copyQ(temp.begin() + n + n / 4, temp.end());

#define B copyB
#define q copyQ
		/* q can start anywhere between temp+n and temp+n/2 */

		if (w == 1) {
			out[pos >> 3] ^= pi[0] << (pos & 7);
			return;
		}

		for (x = 0; x < n; ++x) A[x] = ((pi[x] ^ 1) << 16) | pi[x ^ 1];
		int32_sort(A, n); /* A = (id<<16)+pibar */

		for (x = 0; x < n; ++x) {
			int32 Ax = A[x];
			int32 px = Ax & 0xffff;
			int32 cx = px;
			if (x < cx) cx = x;
			B[x] = (px << 16) | cx;
		}
		/* B = (p<<16)+c */

		for (x = 0; x < n; ++x) A[x] = (A[x] << 16) | x; /* A = (pibar<<16)+id */
		int32_sort(A, n); /* A = (id<<16)+pibar^-1 */

		for (x = 0; x < n; ++x) A[x] = (A[x] << 16) + (B[x] >> 16); /* A = (pibar^(-1)<<16)+pibar */
		int32_sort(A, n); /* A = (id<<16)+pibar^2 */

		if (w <= 10) {
			for (x = 0; x < n; ++x) B[x] = ((A[x] & 0xffff) << 10) | (B[x] & 0x3ff);

			for (i = 1; i < w - 1; ++i) {
				/* B = (p<<10)+c */

				for (x = 0; x < n; ++x) A[x] = ((B[x] & ~0x3ff) << 6) | x; /* A = (p<<16)+id */
				int32_sort(A, n); /* A = (id<<16)+p^{-1} */

				for (x = 0; x < n; ++x) A[x] = (A[x] << 20) | B[x]; /* A = (p^{-1}<<20)+(p<<10)+c */
				int32_sort(A, n); /* A = (id<<20)+(pp<<10)+cp */

				for (x = 0; x < n; ++x) {
					int32 ppcpx = A[x] & 0xfffff;
					int32 ppcx = (A[x] & 0xffc00) | (B[x] & 0x3ff);
					if (ppcpx < ppcx) ppcx = ppcpx;
					B[x] = ppcx;
				}
			}
			for (x = 0; x < n; ++x) B[x] &= 0x3ff;
		}
		else {
			for (x = 0; x < n; ++x) B[x] = (A[x] << 16) | (B[x] & 0xffff);

			for (i = 1; i < w - 1; ++i) {
				/* B = (p<<16)+c */

				for (x = 0; x < n; ++x) A[x] = (B[x] & ~0xffff) | x;
				int32_sort(A, n); /* A = (id<<16)+p^(-1) */

				for (x = 0; x < n; ++x) A[x] = (A[x] << 16) | (B[x] & 0xffff);
				/* A = p^(-1)<<16+c */

				if (i < w - 2) {
					for (x = 0; x < n; ++x) B[x] = (A[x] & ~0xffff) | (B[x] >> 16);
					/* B = (p^(-1)<<16)+p */
					int32_sort(B, n); /* B = (id<<16)+p^(-2) */
					for (x = 0; x < n; ++x) B[x] = (B[x] << 16) | (A[x] & 0xffff);
					/* B = (p^(-2)<<16)+c */
				}

				int32_sort(A, n);
				/* A = id<<16+cp */
				for (x = 0; x < n; ++x) {
					int32 cpx = (B[x] & ~0xffff) | (A[x] & 0xffff);
					if (cpx < B[x]) B[x] = cpx;
				}
			}
			for (x = 0; x < n; ++x) B[x] &= 0xffff;
		}

		for (x = 0; x < n; ++x) A[x] = (static_cast<int32>(pi[x]) << 16) + x;
		int32_sort(A, n); /* A = (id<<16)+pi^(-1) */

		for (j = 0; j < n / 2; ++j) {
			long long x = 2 * j;
			int32 fj = B[x] & 1; /* f[j] */
			int32 Fx = x + fj; /* F[x] */
			int32 Fx1 = Fx ^ 1; /* F[x+1] */

			out[pos >> 3] ^= fj << (pos & 7);
			pos += step;

			B[x] = (A[x] << 16) | Fx;
			B[x + 1] = (A[x + 1] << 16) | Fx1;
		}
		/* B = (pi^(-1)<<16)+F */

		int32_sort(B, n); /* B = (id<<16)+F(pi) */

		pos += (2 * w - 3) * step * (n / 2);

		for (k = 0; k < n / 2; ++k) {
			long long y = 2 * k;
			int32 lk = B[y] & 1; /* l[k] */
			int32 Ly = y + lk; /* L[y] */
			int32 Ly1 = Ly ^ 1; /* L[y+1] */

			out[pos >> 3] ^= lk << (pos & 7);
			pos += step;

			A[y] = (Ly << 16) | (B[y] & 0xffff);
			A[y + 1] = (Ly1 << 16) | (B[y + 1] & 0xffff);
		}
		/* A = (L<<16)+F(pi) */

		int32_sort(A, n); /* A = (id<<16)+F(pi(L)) = (id<<16)+M */

		pos -= (2 * w - 2) * step * (n / 2);

		for (j = 0; j < n / 2; ++j) {
			q[j] = (A[2 * j] & 0xffff) >> 1;
			q[j + n / 2] = (A[2 * j + 1] & 0xffff) >> 1;
		}

		cbrecursion(out, pos, step * 2, q, w - 1, n / 2, temp);
		vector<int16> copy(copyQ.begin() + n / 2, copyQ.end());
		cbrecursion(out, pos + step, step * 2, copy, w - 1, n / 2, temp);
		copyQ.insert(copyQ.begin() + n / 2, copy.begin(), copy.end());
		copyQ.resize(n / 2 + copy.size());
		temp.insert(temp.begin() + n, copyB.begin(), copyB.end());
		temp.resize(n + copyB.size());
		temp.insert(temp.begin() + n + n / 4, copyQ.begin(), copyQ.end());
		temp.resize(n + n / 4 + copyQ.size());
	}

	/* input: p, an array of int16 */
	/* input: n, length of p */
	/* input: s, meaning that stride-2^s cswaps are performed */
	/* input: cb, the control bits */
	/* output: the result of apply the control bits to p */
	static void layer(vector<int16_t>& p, const vector<uint8_t>& cb, uint32_t s, uint32_t n)
	{
		uint32_t i, j;
		uint32_t stride = 1 << s;
		uint32_t index = 0;
		int16_t d, m;

		for (i = 0; i < n; i += stride * 2)
		{
			for (j = 0; j < stride; j++)
			{
				d = p[i + j] ^ p[i + j + stride];
				m = (cb[index >> 3] >> (index & 7)) & 1;
				m = -m;
				d &= m;
				p[i + j] ^= d;
				p[i + j + stride] ^= d;
				index++;
			}
		}
	}

	/* parameters: 1 <= w <= 14; n = 2^w */
	/* input: permutation pi of {0,1,...,n-1} */
	/* output: (2m-1)n/2 control bits at positions 0,1,... */
	/* output position pos is by definition 1&(out[pos/8]>>(pos&7)) */
	void controlbitsfrompermutation(vector<uint8_t>& out, const vector<int16>& pi, uint64_t w, uint64_t n)
	{
		vector<int32> temp(2 * n);
		vector<int16> pi_test(n);
		int16 diff;
		int32_t i;
		uint8_t ptr;

		while (1)
		{
			out.clear();
			out.insert(out.begin(), (((2 * w - 1) * n / 2) + 7) / 8, 0);
			cbrecursion(out, 0, 1, pi, w, n, temp);

			// check for correctness

			for (i = 0; i < n; i++)
				pi_test[i] = i;

			ptr = 0;
			for (i = 0; i < w; i++)
			{
				vector<uint8_t> copy(out.begin() + ptr, out.end());
				layer(pi_test, copy, i, n);
				out.insert(out.begin() + ptr, copy.begin(), copy.end());
				out.resize(ptr + copy.size());
				ptr += n >> 4;
			}

			for (i = w - 2; i >= 0; i--)
			{
				vector<uint8_t> copy(out.begin() + ptr, out.end());
				layer(pi_test, copy, i, n);
				out.insert(out.begin() + ptr, copy.begin(), copy.end());
				out.resize(ptr + copy.size());
				ptr += n >> 4;
			}

			diff = 0;
			for (i = 0; i < n; i++)
				diff |= pi[i] ^ pi_test[i];

			if (diff == 0)
				break;
		}
	}

}
