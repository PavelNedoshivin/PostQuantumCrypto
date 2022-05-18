#ifndef CLASSIC_MCELIECE_UTILS_H
#define CLASSIC_MCELIECE_UTILS_H

#include <vector>
#include <random>
#include <cstdint>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <climits>
#include <cinttypes>

#include <windows.h>
#include <wincrypt.h>

#define SYS_N 3488
#define SYS_T 64
#define GFBITS 12
#define PK_NROWS (SYS_T*GFBITS)
#define SYND_BYTES ((PK_NROWS + 7)/8)
#define RNG_SUCCESS      0
#define GFMASK ((1 << GFBITS) - 1)
#define PK_NCOLS (SYS_N - PK_NROWS)
#define PK_ROW_BYTES ((PK_NCOLS + 7)/8)
#define IRR_BYTES (SYS_T * 2)
#define COND_BYTES ((1 << (GFBITS-4))*(2*GFBITS - 1))

#define uint64_MINMAX(a,b) \
do { \
  int64_t c = b - a; \
  c >>= 63; \
  c = -c; \
  c &= a ^ b; \
  a ^= c; \
  b ^= c; \
} while(0)
#define int32_MINMAX(a,b) \
do { \
  int32_t ab = b ^ a; \
  int32_t c = b - a; \
  c ^= ab & (c ^ b); \
  c >>= 31; \
  c &= ab; \
  a ^= c; \
  b ^= c; \
} while(0)

namespace ClassicMcEliece {

	typedef uint16_t gf;
	typedef int16_t int16;
	typedef int32_t int32;

	uint16_t load_gf(const std::vector<uint8_t>& src);
	void randombytes(std::vector<uint8_t>& out, size_t outlen);
	gf bitrev(gf a);
	uint64_t load8(const std::vector<uint8_t>& in);
	void transpose_64x64(std::vector<uint64_t>& out, std::vector<uint64_t>& in);
	uint32_t load4(const std::vector<uint8_t>& in);
	void store8(std::vector<uint8_t>& out, uint64_t in);
	void apply_benes(std::vector<uint8_t>& r, std::vector<uint8_t>& bits, uint32_t rev);
	void support_gen(std::vector<gf>& s, std::vector<uint8_t>& c);
	gf gf_mul(gf in0, gf in1);
	gf gf_add(gf in0, gf in1);
	gf eval(std::vector<gf>& f, gf a);
	gf gf_inv(gf in);
	void synd(std::vector<gf>& out, std::vector<gf>& f, std::vector<gf>& L, std::vector<uint8_t>& r);
	gf gf_frac(gf den, gf num);
	void bm(std::vector<gf>& out, std::vector<gf>& s);
	void root(std::vector<gf>& out, std::vector<gf>& f, std::vector<gf>& L);
	gf gf_iszero(gf a);
	void GF_mul(std::vector<gf>& out, std::vector<gf>& in0, std::vector<gf>& in1);
	uint32_t genpoly_gen(std::vector<gf>& out, std::vector<gf>& f);
	void store_gf(std::vector<uint8_t>& dest, gf a);
	void controlbitsfrompermutation(std::vector<uint8_t>& out, const std::vector<int16>& pi, uint64_t w, uint64_t n);

}

#endif