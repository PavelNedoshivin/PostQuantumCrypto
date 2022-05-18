#include "NTRU.hpp"

using namespace std;

namespace NTRU {

	void owcpa_keypair(vector<uint8_t>& pk,
		vector<uint8_t>& sk,
		vector<uint8_t>& seed)
	{
		uint32_t i;

		poly x1, x2, x3, x4, x5;
		x1.coeffs.resize(NTRU_N);
		x2.coeffs.resize(NTRU_N);
		x3.coeffs.resize(NTRU_N);
		x4.coeffs.resize(NTRU_N);
		x5.coeffs.resize(NTRU_N);

		poly f = x1, g = x2, invf_mod3 = x3;
		poly gf = x3, invgf = x4, tmp = x5;
		poly invh = x3, h = x3;

		sample_fg(f, g, seed);

		poly_S3_inv(invf_mod3, f);
		poly_S3_tobytes(sk, f);
		vector<uint8_t> copy(sk.begin() + NTRU_PACK_TRINARY_BYTES, sk.end());
		poly_S3_tobytes(copy, invf_mod3);
		sk.insert(sk.begin() + NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		sk.resize(NTRU_PACK_TRINARY_BYTES + copy.size());

		/* Lift coeffs of f and g from Z_p to Z_q */
		poly_Z3_to_Zq(f);
		poly_Z3_to_Zq(g);

		/* g = 3*g */
		for (i = 0; i < NTRU_N; i++)
			g.coeffs[i] = 3 * g.coeffs[i];

		poly_Rq_mul(gf, g, f);

		poly_Rq_inv(invgf, gf);

		poly_Rq_mul(tmp, invgf, f);
		poly_Sq_mul(invh, tmp, f);
		copy.clear();
		copy.insert(copy.begin(), sk.begin() + 2 * NTRU_PACK_TRINARY_BYTES, sk.end());
		poly_Sq_tobytes(copy, invh);
		sk.insert(sk.begin() + 2 * NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		sk.resize(2 * NTRU_PACK_TRINARY_BYTES + copy.size());

		poly_Rq_mul(tmp, invgf, g);
		poly_Rq_mul(h, tmp, g);
		poly_Rq_sum_zero_tobytes(pk, h);
	}

	uint32_t crypto_kem_keypair(vector<uint8_t>& pk, vector<uint8_t>& sk)
	{
		vector<uint8_t> seed(NTRU_SAMPLE_FG_BYTES);

		randombytes(seed, NTRU_SAMPLE_FG_BYTES);
		owcpa_keypair(pk, sk, seed);

		vector<uint8_t> copy(sk.begin() + NTRU_OWCPA_SECRETKEYBYTES, sk.end());
		randombytes(copy, NTRU_PRFKEYBYTES);
		sk.insert(sk.begin() + NTRU_OWCPA_SECRETKEYBYTES, copy.begin(), copy.end());
		sk.resize(NTRU_OWCPA_SECRETKEYBYTES + copy.size());

		return 0;
	}

	void owcpa_enc(vector<uint8_t>& c,
		const poly& r,
		const poly& m,
		const vector<uint8_t>& pk)
	{
		int i;
		poly x1, x2;
		poly h = x1, liftm = x1;
		poly ct = x2;

		poly_Rq_sum_zero_frombytes(h, pk);

		poly_Rq_mul(ct, r, h);

		poly_lift(liftm, m);
		for (i = 0; i < NTRU_N; i++)
			ct.coeffs[i] = ct.coeffs[i] + liftm.coeffs[i];

		poly_Rq_sum_zero_tobytes(c, ct);
	}

	uint32_t crypto_kem_enc(vector<uint8_t>& c, vector<uint8_t>& k, const vector<uint8_t>& pk)
	{
		poly r, m;
		vector<uint8_t> rm(NTRU_OWCPA_MSGBYTES);
		vector<uint8_t> rm_seed(NTRU_SAMPLE_RM_BYTES);

		randombytes(rm_seed, NTRU_SAMPLE_RM_BYTES);

		sample_rm(r, m, rm_seed);

		poly_S3_tobytes(rm, r);
		vector<uint8_t> copy(rm.begin() + NTRU_PACK_TRINARY_BYTES, rm.end());
		poly_S3_tobytes(copy, m);
		rm.insert(rm.begin() + NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		rm.resize(NTRU_PACK_TRINARY_BYTES + copy.size());
		crypto_hash_sha3256(k, rm, NTRU_OWCPA_MSGBYTES);

		poly_Z3_to_Zq(r);
		owcpa_enc(c, r, m, pk);

		return 0;
	}

	static uint32_t owcpa_check_ciphertext(const vector<uint8_t>& ciphertext)
	{
		/* A ciphertext is log2(q)*(n-1) bits packed into bytes.  */
		/* Check that any unused bits of the final byte are zero. */

		uint16_t t = 0;

		t = ciphertext[NTRU_CIPHERTEXTBYTES - 1];
		t &= 0xff << (8 - (7 & (NTRU_LOGQ * NTRU_PACK_DEG)));

		/* We have 0 <= t < 256 */
		/* Return 0 on success (t=0), 1 on failure */
		return static_cast<uint32_t>(1 & ((~t + 1) >> 15));
	}

	static uint32_t owcpa_check_r(const poly& r)
	{
		/* A valid r has coefficients in {0,1,q-1} and has r[N-1] = 0 */
		/* Note: We may assume that 0 <= r[i] <= q-1 for all i        */

		uint32_t i;
		uint32_t t = 0;
		uint16_t c;
		for (i = 0; i < NTRU_N - 1; i++)
		{
			c = r.coeffs[i];
			t |= (c + 1) & (NTRU_Q - 4);  /* 0 iff c is in {-1,0,1,2} */
			t |= (c + 2) & 4;  /* 1 if c = 2, 0 if c is in {-1,0,1} */
		}
		t |= r.coeffs[NTRU_N - 1]; /* Coefficient n-1 must be zero */

		/* We have 0 <= t < 2^16. */
		/* Return 0 on success (t=0), 1 on failure */
		return static_cast<uint32_t>(1 & ((~t + 1) >> 31));
	}

	uint32_t owcpa_dec(vector<uint8_t>& rm,
		const vector<uint8_t>& ciphertext,
		vector<uint8_t>& secretkey)
	{
		uint32_t i;
		uint32_t fail;
		poly x1, x2, x3, x4;

		poly c = x1, f = x2, cf = x3;
		poly mf = x2, finv3 = x3, m = x4;
		poly liftm = x2, invh = x3, r = x4;
		poly b = x1;

		poly_Rq_sum_zero_frombytes(c, ciphertext);
		poly_S3_frombytes(f, secretkey);
		poly_Z3_to_Zq(f);

		poly_Rq_mul(cf, c, f);
		poly_Rq_to_S3(mf, cf);

		vector<uint8_t> copy(secretkey.begin() + NTRU_PACK_TRINARY_BYTES, secretkey.end());
		poly_S3_frombytes(finv3, copy);
		secretkey.insert(secretkey.begin() + NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		secretkey.resize(NTRU_PACK_TRINARY_BYTES + copy.size());
		poly_S3_mul(m, mf, finv3);
		copy.clear();
		copy.insert(copy.begin(), rm.begin() + NTRU_PACK_TRINARY_BYTES, rm.end());
		poly_S3_tobytes(copy, m);
		rm.insert(rm.begin() + NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		rm.resize(NTRU_PACK_TRINARY_BYTES + copy.size());

		fail = 0;

		/* Check that the unused bits of the last byte of the ciphertext are zero */
		fail |= owcpa_check_ciphertext(ciphertext);

		/* For the IND-CCA2 KEM we must ensure that c = Enc(h, (r,m)).             */
		/* We can avoid re-computing r*h + Lift(m) as long as we check that        */
		/* r (defined as b/h mod (q, Phi_n)) and m are in the message space.       */
		/* (m can take any value in S3 in NTRU_HRSS) */
#ifdef NTRU_HPS
		fail |= owcpa_check_m(m);
#endif

		/* b = c - Lift(m) mod (q, x^n - 1) */
		poly_lift(liftm, m);
		for (i = 0; i < NTRU_N; i++)
			b.coeffs[i] = c.coeffs[i] - liftm.coeffs[i];

		/* r = b / h mod (q, Phi_n) */
		copy.clear();
		copy.insert(copy.begin(), secretkey.begin() + 2 * NTRU_PACK_TRINARY_BYTES, secretkey.end());
		poly_Sq_frombytes(invh, copy);
		secretkey.insert(secretkey.begin() + 2 * NTRU_PACK_TRINARY_BYTES, copy.begin(), copy.end());
		secretkey.resize(2 * NTRU_PACK_TRINARY_BYTES + copy.size());
		poly_Sq_mul(r, b, invh);

		/* NOTE: Our definition of r as b/h mod (q, Phi_n) follows Figure 4 of     */
		/*   [Sch18] https://eprint.iacr.org/2018/1174/20181203:032458.            */
		/* This differs from Figure 10 of Saito--Xagawa--Yamakawa                  */
		/*   [SXY17] https://eprint.iacr.org/2017/1005/20180516:055500             */
		/* where r gets a final reduction modulo p.                                */
		/* We need this change to use Proposition 1 of [Sch18].                    */

		/* Proposition 1 of [Sch18] shows that re-encryption with (r,m) yields c.  */
		/* if and only if fail==0 after the following call to owcpa_check_r        */
		/* The procedure given in Fig. 8 of [Sch18] can be skipped because we have */
		/* c(1) = 0 due to the use of poly_Rq_sum_zero_{to,from}bytes.             */
		fail |= owcpa_check_r(r);

		poly_trinary_Zq_to_Z3(r);
		poly_S3_tobytes(rm, r);

		return fail;
	}

	uint32_t crypto_kem_dec(vector<uint8_t>& k, const vector<uint8_t>& c, vector<uint8_t>& sk)
	{
		uint32_t i, fail;
		vector<uint8_t> rm(NTRU_OWCPA_MSGBYTES);
		vector<uint8_t> buf(NTRU_PRFKEYBYTES + NTRU_CIPHERTEXTBYTES);

		fail = owcpa_dec(rm, c, sk);
		/* If fail = 0 then c = Enc(h, rm). There is no need to re-encapsulate. */
		/* See comment in owcpa_dec for details.                                */

		crypto_hash_sha3256(k, rm, NTRU_OWCPA_MSGBYTES);

		/* shake(secret PRF key || input ciphertext) */
		for (i = 0; i < NTRU_PRFKEYBYTES; i++)
			buf[i] = sk[i + NTRU_OWCPA_SECRETKEYBYTES];
		for (i = 0; i < NTRU_CIPHERTEXTBYTES; i++)
			buf[NTRU_PRFKEYBYTES + i] = c[i];
		crypto_hash_sha3256(rm, buf, NTRU_PRFKEYBYTES + NTRU_CIPHERTEXTBYTES);

		cmov(k, rm, NTRU_SHAREDKEYBYTES, static_cast<uint8_t>(fail));

		return 0;
	}

}
