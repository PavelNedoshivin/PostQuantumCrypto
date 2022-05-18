#include "ClassicMcEliece.hpp"

using namespace std;

namespace ClassicMcEliece {

	static inline uint8_t same_mask(uint16_t x, uint16_t y)
	{
		int32_t mask;

		mask = x ^ y;
		mask -= 1;
		mask >>= 31;
		mask = -mask;

		return mask & 0xFF;
	}

	/* output: e, an error vector of weight t */
	static void gen_e(vector<uint8_t>& e)
	{
		uint32_t i, j, eq, count;

		struct
		{
			vector<uint16_t> nums;
			vector<uint8_t> bytes;
		} buf;
		buf.nums.resize(SYS_T * 2);
		buf.bytes.resize(SYS_T * 2 * sizeof(uint16_t));

		vector<uint16_t> ind(SYS_T);
		uint8_t mask;
		vector<uint8_t> val(SYS_T);

		while (1)
		{
			uint64_t bufSize = sizeof(uint16_t) * SYS_T * 2 + sizeof(uint8_t) * SYS_T * 2 * sizeof(uint16_t);
			ClassicMcEliece::randombytes(buf.bytes, bufSize);

			for (i = 0; i < SYS_T * 2; i++) {
				vector<uint8_t> copy(buf.bytes.begin() + i * 2, buf.bytes.end());
				buf.nums[i] = load_gf(copy);
				buf.bytes.insert(buf.bytes.begin() + i * 2, copy.begin(), copy.end());
				buf.bytes.resize(i * 2 + copy.size());
			}

			// moving and counting indices in the correct range

			count = 0;
			for (i = 0; i < SYS_T * 2 && count < SYS_T; i++)
				if (buf.nums[i] < SYS_N)
					ind[count++] = buf.nums[i];

			if (count < SYS_T) continue;

			// check for repetition

			eq = 0;

			for (i = 1; i < SYS_T; i++)
				for (j = 0; j < i; j++)
					if (ind[i] == ind[j])
						eq = 1;

			if (eq == 0)
				break;
		}

		for (j = 0; j < SYS_T; j++)
			val[j] = 1 << (ind[j] & 7);

		for (i = 0; i < SYS_N / 8; i++)
		{
			e[i] = 0;

			for (j = 0; j < SYS_T; j++)
			{
				mask = same_mask(i, (ind[j] >> 3));

				e[i] |= val[j] & mask;
			}
		}
	}

	/* input: public key pk, error vector e */
	/* output: syndrome s */
	static void syndrome(vector<uint8_t>& s, const vector<uint8_t>& pk, vector<uint8_t>& e)
	{
		uint8_t b;
		vector<uint8_t> row(SYS_N / 8);
		uint32_t pk_ptr = 0;

		uint32_t i, j;

		for (i = 0; i < SYND_BYTES; i++)
			s[i] = 0;

		for (i = 0; i < PK_NROWS; i++)
		{
			for (j = 0; j < SYS_N / 8; j++)
				row[j] = 0;

			for (j = 0; j < PK_ROW_BYTES; j++)
				row[SYS_N / 8 - PK_ROW_BYTES + j] = pk[pk_ptr + j];

			row[i / 8] |= 1 << (i % 8);

			b = 0;
			for (j = 0; j < SYS_N / 8; j++)
				b ^= row[j] & e[j];

			b ^= b >> 4;
			b ^= b >> 2;
			b ^= b >> 1;
			b &= 1;

			s[i / 8] |= (b << (i % 8));

			pk_ptr += PK_ROW_BYTES;
		}
	}

	void encrypt(vector<uint8_t>& s, const vector<uint8_t>& pk, vector<uint8_t>& e)
	{
		gen_e(e);
		syndrome(s, pk, e);
	}

	uint32_t crypto_kem_enc(
		vector<uint8_t>& c,
		vector<uint8_t>& key,
		const vector<uint8_t>& pk
	)
	{
		vector<uint8_t> two_e(1 + SYS_N / 8, 2);
		vector<uint8_t> e(two_e.begin() + 1, two_e.end());
		vector<uint8_t> one_ec(1 + SYS_N / 8 + (SYND_BYTES + 32), 1);

		//

		encrypt(c, pk, e);

		vector<uint8_t> copy(c.begin() + SYND_BYTES, c.end());
		uint32_t size = sizeof(uint8_t) * (1 + SYS_N / 8);
		crypto_hash_32b(copy, two_e, size);
		c.insert(c.begin() + SYND_BYTES, copy.begin(), copy.end());
		c.resize(SYND_BYTES + copy.size());

	
		one_ec.insert(one_ec.begin() + 1, e.begin(), e.begin() + SYS_N / 8);
		one_ec.resize(1 + SYS_N / 8);
		one_ec.insert(one_ec.begin() + 1 + SYS_N / 8, c.begin(), c.begin() + SYND_BYTES + 32);
		one_ec.resize(1 + SYS_N / 8 + SYND_BYTES + 32);

		size = sizeof(uint8_t) * (1 + SYS_N / 8 + (SYND_BYTES + 32));
		crypto_hash_32b(key, one_ec, size);

		return 0;
	}

	/* Niederreiter decryption with the Berlekamp decoder */
	/* intput: sk, secret key */
	/*         c, ciphertext */
	/* output: e, error vector */
	/* return: 0 for success; 1 for failure */
	uint32_t decrypt(vector<uint8_t>& e, vector<uint8_t>& sk, const vector<uint8_t>& c)
	{
		uint32_t i, w = 0;
		uint16_t check;

		vector<uint8_t>  r(SYS_N / 8);

		vector<gf> g(SYS_T + 1);
		vector<gf> L(SYS_N);

		vector<gf> s(SYS_T * 2);
		vector<gf> s_cmp(SYS_T * 2);
		vector<gf> locator(SYS_T + 1);
		vector<gf> images(SYS_N);

		gf t;

		//

		for (i = 0; i < SYND_BYTES; i++)       r[i] = c[i];
		for (i = SYND_BYTES; i < SYS_N / 8; i++) r[i] = 0;

		uint32_t sk_ptr = 0;

		for (i = 0; i < SYS_T; i++) { 
			vector<uint8_t> copy(sk.begin() + sk_ptr, sk.end());
			g[i] = load_gf(sk);
			sk.insert(sk.begin() + sk_ptr, copy.begin(), copy.end());
			sk.resize(sk_ptr + copy.size());
			sk_ptr += 2; 
		} 
		g[SYS_T] = 1;

		support_gen(L, sk);

		synd(s, g, L, r);

		bm(locator, s);

		root(images, locator, L);

		//

		for (i = 0; i < SYS_N / 8; i++)
			e[i] = 0;

		for (i = 0; i < SYS_N; i++)
		{
			t = gf_iszero(images[i]) & 1;

			e[i / 8] |= t << (i % 8);
			w += t;

		}

		synd(s_cmp, g, L, e);

		//

		check = w;
		check ^= SYS_T;

		for (i = 0; i < SYS_T * 2; i++)
			check |= s[i] ^ s_cmp[i];

		check -= 1;
		check >>= 15;

		return check ^ 1;
	}

	uint32_t crypto_kem_dec(
		vector<uint8_t>& key,
		const vector<uint8_t>& c,
		vector<uint8_t>& sk
	)
	{
		uint32_t i;

		uint8_t ret_confirm = 0;
		uint8_t ret_decrypt = 0;

		uint16_t m;

		vector<uint8_t> conf(32);
		vector<uint8_t> two_e(1 + SYS_N / 8, 2);
		vector<uint8_t> e(two_e.begin() + 1, two_e.end());
		vector<uint8_t> preimage(1 + SYS_N / 8 + (SYND_BYTES + 32));
		uint8_t x = 0;
		const vector<uint8_t> s(sk.begin() + 40 + IRR_BYTES + COND_BYTES, sk.end());

		//

		vector<uint8_t> copy(sk.begin() + 40, sk.end());
		ret_decrypt = decrypt(e, copy, c);
		sk.insert(sk.begin() + 40, copy.begin(), copy.end());
		sk.resize(40 + copy.size());

		uint32_t size = sizeof(uint8_t) * (1 + SYS_N / 8);
		crypto_hash_32b(conf, two_e, size);

		for (i = 0; i < 32; i++)
			ret_confirm |= conf[i] ^ c[SYND_BYTES + i];

		m = ret_decrypt | ret_confirm;
		m -= 1;
		m >>= 8;

		preimage[x++] = m & 1;
		for (i = 0; i < SYS_N / 8; i++)
			preimage[x++] = (~m & s[i]) | (m & e[i]);

		for (i = 0; i < SYND_BYTES + 32; i++)
			preimage[x++] = c[i];

		size = sizeof(uint8_t) * (1 + SYS_N / 8 + (SYND_BYTES + 32));
		crypto_hash_32b(key, preimage, size);

		return 0;
	}

	static void uint64_sort(vector<int64_t>& x, uint64_t n)
	{
		uint64_t top, p, q, r, i;

		if (n < 2) return;
		top = 1;
		while (top < n - top) top += top;

		for (p = top; p > 0; p >>= 1) {
			for (i = 0; i < n - p; ++i)
				if (!(i & p))
					uint64_MINMAX(x[i], x[i + p]);
			i = 0;
			for (q = top; q > p; q >>= 1) {
				for (; i < n - q; ++i) {
					if (!(i & p)) {
						int64_t a = x[i + p];
						for (r = q; r > p; r >>= 1)
							uint64_MINMAX(a, x[i + r]);
						x[i + p] = a;
					}
				}
			}
		}
	}

	/* input: secret key sk */
	/* output: public key pk */
	uint32_t pk_gen(vector<uint8_t>& pk, vector<uint8_t>& sk, vector<uint32_t>& perm, vector<int16_t>& pi)
	{
		uint32_t i, j, k;
		uint32_t row, c;

		vector<int64_t> buf(1 << GFBITS);

		vector<vector<uint8_t>> mat(PK_NROWS);
		for (i = 0; i < PK_NROWS; i++) {
			mat[i].resize(SYS_N / 8);
		}
		uint8_t mask;
		uint8_t b;

		vector<gf> g(SYS_T + 1); // Goppa polynomial
		vector<gf> L(SYS_N); // support
		vector<gf> inv(SYS_N);

		//

		g[SYS_T] = 1;

		uint32_t sk_ptr = 0;

		for (i = 0; i < SYS_T; i++) { 
			vector<uint8_t> copy(sk.begin() + sk_ptr, sk.end());
			g[i] = load_gf(sk);
			sk.insert(sk.begin() + sk_ptr, copy.begin(), copy.end());
			sk.resize(sk_ptr + copy.size());
			sk_ptr += 2;
		}

		for (i = 0; i < (1 << GFBITS); i++)
		{
			buf[i] = perm[i];
			buf[i] <<= 31;
			buf[i] |= i;
		}

		uint64_sort(buf, 1 << GFBITS);

		for (i = 1; i < (1 << GFBITS); i++)
			if ((buf[i - 1] >> 31) == (buf[i] >> 31))
				return -1;

		for (i = 0; i < (1 << GFBITS); i++) pi[i] = buf[i] & GFMASK;
		for (i = 0; i < SYS_N; i++) L[i] = bitrev(pi[i]);

		// filling the matrix

		root(inv, g, L);

		for (i = 0; i < SYS_N; i++)
			inv[i] = gf_inv(inv[i]);

		for (i = 0; i < PK_NROWS; i++)
			for (j = 0; j < SYS_N / 8; j++)
				mat[i][j] = 0;

		for (i = 0; i < SYS_T; i++)
		{
			for (j = 0; j < SYS_N; j += 8)
				for (k = 0; k < GFBITS; k++)
				{
					b = (inv[j + 7] >> k) & 1; b <<= 1;
					b |= (inv[j + 6] >> k) & 1; b <<= 1;
					b |= (inv[j + 5] >> k) & 1; b <<= 1;
					b |= (inv[j + 4] >> k) & 1; b <<= 1;
					b |= (inv[j + 3] >> k) & 1; b <<= 1;
					b |= (inv[j + 2] >> k) & 1; b <<= 1;
					b |= (inv[j + 1] >> k) & 1; b <<= 1;
					b |= (inv[j + 0] >> k) & 1;

					mat[i * GFBITS + k][j / 8] = b;
				}

			for (j = 0; j < SYS_N; j++)
				inv[j] = gf_mul(inv[j], L[j]);

		}

		// gaussian elimination

		for (i = 0; i < (PK_NROWS + 7) / 8; i++)
			for (j = 0; j < 8; j++)
			{
				row = i * 8 + j;

				if (row >= PK_NROWS)
					break;

				for (k = row + 1; k < PK_NROWS; k++)
				{
					mask = mat[row][i] ^ mat[k][i];
					mask >>= j;
					mask &= 1;
					mask = -mask;

					for (c = 0; c < SYS_N / 8; c++)
						mat[row][c] ^= mat[k][c] & mask;
				}

				if (((mat[row][i] >> j) & 1) == 0) // return if not systematic
				{
					return -1;
				}

				for (k = 0; k < PK_NROWS; k++)
				{
					if (k != row)
					{
						mask = mat[k][i] >> j;
						mask &= 1;
						mask = -mask;

						for (c = 0; c < SYS_N / 8; c++)
							mat[k][c] ^= mat[row][c] & mask;
					}
				}
			}

		for (i = 0; i < PK_NROWS; i++) {
			pk.insert(pk.begin() + i * PK_ROW_BYTES, mat[i].begin() + PK_NROWS / 8, mat[i].begin() + PK_NROWS / 8 + PK_ROW_BYTES);
			pk.resize(i * PK_ROW_BYTES + PK_NROWS / 8 + PK_ROW_BYTES - PK_NROWS / 8);
		}

		return 0;
	}

	uint32_t crypto_kem_keypair
	(
		vector<uint8_t>& pk,
		vector<uint8_t>& sk
	)
	{
		uint32_t i;
		vector<uint8_t> seed(33, 64);
		vector<uint8_t> r(SYS_N / 8 + (1 << GFBITS) * sizeof(uint32_t) + SYS_T * 2 + 32);
		uint32_t rp;
		uint32_t skp;

		vector<gf> f(SYS_T); // element in GF(2^mt)
		vector<gf> irr(SYS_T); // Goppa polynomial
		vector<uint32_t> perm(1 << GFBITS); // random permutation as 32-bit integers
		vector<int16_t> pi(1 << GFBITS); // random permutation

		vector<uint8_t> copy(seed.begin() + 1, seed.end());
		ClassicMcEliece::randombytes(copy, 32);
		seed.insert(seed.begin() + 1, copy.begin(), copy.end());
		seed.resize(1 + copy.size());

		while (1)
		{
			uint32_t size = sizeof(uint8_t) * (SYS_N / 8 + (1 << GFBITS) * sizeof(uint32_t) + SYS_T * 2 + 32);
			rp = size - 32;
			skp = 0;

			// expanding and updating the seed

			shake(r, size, seed, 33);
			sk.insert(sk.begin() + skp, seed.begin() + 1, seed.begin() + 33);
			sk.resize(skp + 33 - 1);
			skp += 32 + 8;
			seed.insert(seed.begin() + 1, r.begin() + r.size() - 32, r.begin() + r.size());
			seed.resize(1 + 32);

			// generating irreducible polynomial

			size = sizeof(gf) * SYS_T;
			rp = 0; // ???

			for (i = 0; i < r.size() / 2; i++) {
				vector<uint8_t> copy(r.begin() + rp + i * 2, r.end());
				f[i] = load_gf(copy);
				r.insert(r.begin() + rp + i * 2, copy.begin(), copy.end());
				r.resize(rp + i * 2 + copy.size());
			}

			if (genpoly_gen(irr, f))
				continue;

			for (i = 0; i < SYS_T; i++) {
				vector<uint8_t> copy(sk.begin() + skp + i * 2, sk.end());
				store_gf(copy, irr[i]);
				sk.insert(sk.begin() + skp + i * 2, copy.begin(), copy.end());
				sk.resize(skp + i * 2 + copy.size());
			}

			skp += IRR_BYTES;

			// generating permutation

			size = sizeof(uint32_t) * (1 << GFBITS);
			rp = 0; /// ???

			for (i = 0; i < r.size() / 4; i++) {
				vector<uint8_t> copy(r.begin() + rp + i * 4, r.end());
				perm[i] = load4(copy);
				r.insert(r.begin() + rp + i * 4, copy.begin(), copy.end());
				r.resize(rp + i * 4 + copy.size());
			}

			vector<uint8_t> copy(sk.begin() + skp - IRR_BYTES, sk.end());
			if (pk_gen(pk, copy, perm, pi))
				continue;

			sk.insert(sk.begin() + skp - IRR_BYTES, copy.begin(), copy.end());
			sk.resize(skp - IRR_BYTES + copy.size());
			copy.clear();
			copy.insert(copy.begin(), sk.begin() + skp, sk.end());
			controlbitsfrompermutation(copy, pi, GFBITS, 1 << GFBITS);
			sk.insert(sk.begin() + skp, copy.begin(), copy.end());
			sk.resize(skp + copy.size());
			skp += COND_BYTES;

			// storing the random string s

			rp -= SYS_N / 8;
			sk.insert(sk.begin() + skp, r.begin() + rp, r.begin() + rp + SYS_N / 8);
			sk.resize(skp + SYS_N / 8);

			// storing positions of the 32 pivots

			copy.clear();
			copy.insert(copy.begin(), sk.begin() + 32, sk.end());
			store8(copy, 0xFFFFFFFF);
			sk.insert(sk.begin() + 32, copy.begin(), copy.end());
			sk.resize(32 + copy.size());

			break;
		}

		return 0;
	}

}
