#ifndef CRYSTALS_KYBER_UTILS_H
#define CRYSTALS_KYBER_UTILS_H

#include <vector>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include <windows.h>
#include <wincrypt.h>

#define CRYPTO_BYTES           32 /* size in bytes of shared key */
#define KYBER_SYMBYTES 32   /* size in bytes of hashes, and seeds */
#define KYBER_SSBYTES  32   /* size in bytes of shared key */
#define NROUNDS 24
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define SHAKE128_RATE 168
#define SHAKE256_RATE 136
#define KYBER_N 256
#define KYBER_Q 3329
#define KYBER_K 3	/* Change this for different security strengths */
#define XOF_BLOCKBYTES 128
#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
#define QINV -3327 // q^-1 mod 2^16
#define KYBER_ETA1 2
#define KYBER_ETA2 2
#define KYBER_POLYBYTES		384
#define KYBER_POLYCOMPRESSEDBYTES    128
#define KYBER_POLYVECCOMPRESSEDBYTES (KYBER_K * 320)
#define KYBER_POLYVECBYTES	(KYBER_K * KYBER_POLYBYTES)
#define KYBER_INDCPA_PUBLICKEYBYTES (KYBER_POLYVECBYTES + KYBER_SYMBYTES)
#define KYBER_INDCPA_SECRETKEYBYTES (KYBER_POLYVECBYTES)
#define KYBER_INDCPA_BYTES          (KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES)
#define KYBER_PUBLICKEYBYTES  (KYBER_INDCPA_PUBLICKEYBYTES)
/* 32 bytes of additional space to save H(pk) */
#define KYBER_SECRETKEYBYTES  (KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + 2*KYBER_SYMBYTES)
#define KYBER_CIPHERTEXTBYTES (KYBER_INDCPA_BYTES)
#define CRYPTO_SECRETKEYBYTES  KYBER_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES  KYBER_PUBLICKEYBYTES
#define CRYPTO_CIPHERTEXTBYTES KYBER_CIPHERTEXTBYTES

#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))
#define hash_h(OUT, IN, INBYTES) sha3_256(OUT, IN, INBYTES)
#define hash_g(OUT, IN, INBYTES) sha3_512(OUT, IN, INBYTES)
#define xof_absorb(STATE, SEED, X, Y) kyber_shake128_absorb(STATE, SEED, X, Y)
#define xof_squeezeblocks(OUT, OUTBLOCKS, STATE) shake128_squeezeblocks(OUT, OUTBLOCKS, STATE)
#define gen_a(A,B)  gen_matrix(A,B,0)
#define gen_at(A,B) gen_matrix(A,B,1)
#define prf(OUT, OUTBYTES, KEY, NONCE) kyber_shake256_prf(OUT, OUTBYTES, KEY, NONCE)
#define kdf(OUT, IN, INBYTES) shake256(OUT, KYBER_SSBYTES, IN, INBYTES)

namespace CrystalsKyber {

	struct poly {
		std::vector<int16_t> coeffs;
	};
	struct polyvec {
		std::vector<poly> vec;
	};
	struct keccak_state {
		std::vector<uint64_t> s;
		uint32_t pos;
	};
	typedef keccak_state xof_state;

	const int16_t zetas[128] = {
	  -1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
	   -171,   622,  1577,   182,   962, -1202, -1474,  1468,
		573, -1325,   264,   383,  -829,  1458, -1602,  -130,
	   -681,  1017,   732,   608, -1542,   411,  -205, -1571,
	   1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
		516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
	   -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
	   -398,   961, -1508,  -725,   448, -1065,   677, -1275,
	  -1103,   430,   555,   843, -1251,   871,  1550,   105,
		422,   587,   177,  -235,  -291,  -460,  1574,  1653,
	   -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
	  -1590,   644,  -872,   349,   418,   329,  -156,   -75,
		817,  1097,   603,   610,  1322, -1285, -1465,   384,
	  -1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
	  -1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
	   -108,  -308,   996,   991,   958, -1460,  1522,  1628
	};

	void randombytes(std::vector<uint8_t>& out, size_t outlen);
	void sha3_512(std::vector<uint8_t>& h, std::vector<uint8_t>& in, size_t inlen);
	void shake128_absorb_once(keccak_state& state, std::vector<uint8_t>& in, size_t inlen);
	void kyber_shake128_absorb(keccak_state& s, const std::vector<uint8_t>& seed, uint8_t x, uint8_t y);
	void shake128_squeezeblocks(std::vector<uint8_t>& out, size_t nblocks, keccak_state& state);
	void gen_matrix(std::vector<polyvec>& a, const std::vector<uint8_t>& seed, uint32_t transposed);
	void shake256_absorb_once(keccak_state& state, std::vector<uint8_t>& in, size_t inlen);
	void shake256_squeezeblocks(std::vector<uint8_t>& out, size_t nblocks, keccak_state& state);
	void shake256_squeeze(std::vector<uint8_t>& out, size_t outlen, keccak_state& state);
	void shake256(std::vector<uint8_t>& out, size_t outlen, std::vector<uint8_t>& in, size_t inlen);
	void kyber_shake256_prf(std::vector<uint8_t>& out, size_t outlen, const std::vector<uint8_t>& key, uint8_t nonce);
	void poly_cbd_eta1(poly& r, std::vector<uint8_t>& buf);
	void poly_getnoise_eta1(poly& r, const std::vector<uint8_t> seed, uint8_t nonce);
	int16_t montgomery_reduce(int32_t a);
	void ntt(std::vector<int16_t>& poly);
	int16_t barrett_reduce(int16_t a);
	void poly_reduce(poly& r);
	void poly_ntt(poly& r);
	void polyvec_ntt(polyvec& r);
	void basemul(std::vector<int16_t>& r, const std::vector<int16_t>& a, const std::vector<int16_t>& b, int16_t zeta);
	void poly_basemul_montgomery(poly& r, poly& a, poly& b);
	void poly_add(poly& r, const poly& a, const poly& b);
	void polyvec_basemul_acc_montgomery(poly& r, polyvec& a, polyvec& b);
	void poly_tomont(poly& r);
	void polyvec_add(polyvec& r, const polyvec& a, const polyvec& b);
	void polyvec_reduce(polyvec& r);
	void poly_tobytes(std::vector<uint8_t>& r, const poly& a);
	void polyvec_tobytes(std::vector<uint8_t>& r, const polyvec& a);
	void sha3_256(std::vector<uint8_t>& h, std::vector<uint8_t>& in, size_t inlen);
	void poly_frombytes(poly& r, const std::vector<uint8_t>& a);
	void polyvec_frombytes(polyvec& r, std::vector<uint8_t>& a);
	void poly_frommsg(poly& r, const std::vector<uint8_t>& msg);
	void poly_cbd_eta2(poly& r, std::vector<uint8_t>& buf);
	void poly_getnoise_eta2(poly& r, const std::vector<uint8_t>& seed, uint8_t nonce);
	void invntt(std::vector<int16_t>& poly);
	void poly_invntt_tomont(poly& r);
	void polyvec_invntt_tomont(polyvec& r);
	void polyvec_compress(std::vector<uint8_t>& r, const polyvec& a);
	void poly_compress(std::vector<uint8_t>& r, const poly& a);
	void polyvec_decompress(polyvec& r, std::vector<uint8_t>& a);
	void poly_decompress(poly& r, std::vector<uint8_t>& a);
	void poly_sub(poly& r, const poly& a, const poly& b);
	void poly_tomsg(std::vector<uint8_t>& msg, const poly& r);
	uint32_t verify(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, size_t len);
	void cmov(std::vector<uint8_t>& r, const std::vector<uint8_t>& x, size_t len, uint8_t b);


}

#endif