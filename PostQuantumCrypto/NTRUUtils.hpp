#ifndef NTRU_UTILS_H
#define NTRU_UTILS_H

#include <vector>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <chrono>
#include <thread>

#define SHA3_256_RATE 136
#define NROUNDS 24
#define NTRU_N 509
#define NTRU_LOGQ 11
#define NTRU_Q (1 << NTRU_LOGQ)
#define NTRU_WEIGHT (NTRU_Q/8 - 2)
#define NTRU_PRFKEYBYTES     32
#define NTRU_SHAREDKEYBYTES  32
#define NTRU_SAMPLE_IID_BYTES  (NTRU_N-1)
#define NTRU_SAMPLE_FT_BYTES   ((30*(NTRU_N-1)+7)/8)
#define NTRU_SAMPLE_FG_BYTES   (NTRU_SAMPLE_IID_BYTES+NTRU_SAMPLE_FT_BYTES)
#define NTRU_SAMPLE_RM_BYTES   (NTRU_SAMPLE_IID_BYTES+NTRU_SAMPLE_FT_BYTES)
#define NTRU_PACK_DEG (NTRU_N-1)
#define NTRU_PACK_TRINARY_BYTES    ((NTRU_PACK_DEG+4)/5)
#define NTRU_OWCPA_MSGBYTES       (2*NTRU_PACK_TRINARY_BYTES)
#define NTRU_OWCPA_PUBLICKEYBYTES ((NTRU_LOGQ*NTRU_PACK_DEG+7)/8)
#define NTRU_OWCPA_SECRETKEYBYTES (2*NTRU_PACK_TRINARY_BYTES + NTRU_OWCPA_PUBLICKEYBYTES)
#define NTRU_OWCPA_BYTES          ((NTRU_LOGQ*NTRU_PACK_DEG+7)/8)
#define NTRU_CIPHERTEXTBYTES (NTRU_OWCPA_BYTES)
#define MODQ(X) ((X) & (NTRU_Q-1))
#define ROL(a, offset) ((a << offset) ^ (a >> (64-offset)))

#define int32 int32_t
#define int32_MINMAX(a,b) \
do { \
  int32_t ab = (b) ^ (a); \
  int32_t c = static_cast<int32_t>(static_cast<int64_t>(b) - static_cast<int64_t>(a)); \
  c ^= ab & (c ^ (b)); \
  c >>= 31; \
  c &= ab; \
  (a) ^= c; \
  (b) ^= c; \
} while(0)
#define crypto_hash_sha3256 sha3_256


namespace NTRU {

	typedef struct {
		std::vector<uint16_t> coeffs;
	} poly;

	static int32_t fd = -1;

	void randombytes(std::vector<uint8_t>& x, uint64_t xlen);
	void sample_iid(poly& r, const std::vector<uint8_t>& uniformbytes);
	void crypto_sort_int32(std::vector<int32_t>& array, size_t n);
	void sample_fixed_type(poly& r, const std::vector<uint8_t>& uniformbytes);
	void sample_fg(poly& f, poly& g, std::vector<uint8_t>& uniformbytes);
	void poly_S3_inv(poly& r, const poly& a);
	void poly_S3_tobytes(std::vector<uint8_t>& msg, const poly& a);
	void poly_Z3_to_Zq(poly& r);
	void poly_Rq_mul(poly& r, const poly& a, const poly& b);
	void poly_R2_inv(poly& r, const poly& a);
	void poly_Rq_inv(poly& r, const poly& a);
	void poly_mod_q_Phi_n(poly& r);
	void poly_Sq_mul(poly& r, const poly& a, const poly& b);
	void poly_Sq_tobytes(std::vector<uint8_t>& r, const poly& a);
	void poly_Rq_sum_zero_tobytes(std::vector<uint8_t>& r, const poly& a);
	void sample_rm(poly& r, poly& m, const std::vector<uint8_t>& uniformbytes);
	void poly_Sq_frombytes(poly& r, const std::vector<uint8_t>& a);
	void poly_Rq_sum_zero_frombytes(poly& r, const std::vector<uint8_t>& a);
	void poly_lift(poly& r, const poly& a);
	void sha3_256(std::vector<uint8_t>& output, std::vector<uint8_t>& input, uint64_t inlen);
	void poly_mod_3_Phi_n(poly& r);
	void poly_S3_frombytes(poly& r, const std::vector<uint8_t>& msg);
	void poly_Rq_to_S3(poly& r, const poly& a);
	void poly_S3_mul(poly& r, const poly& a, const poly& b);
	void poly_trinary_Zq_to_Z3(poly& r);
	void cmov(std::vector<uint8_t>& r, const std::vector<uint8_t>& x, size_t len, uint8_t b);

}

#endif