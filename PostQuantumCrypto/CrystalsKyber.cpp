#include "CrystalsKyber.hpp"

using namespace std;

namespace CrystalsKyber {

    /*************************************************
* Name:        pack_sk
*
* Description: Serialize the secret key
*
* Arguments:   - uint8_t *r: pointer to output serialized secret key
*              - polyvec *sk: pointer to input vector of polynomials (secret key)
**************************************************/
    static void pack_sk(vector<uint8_t>& r, polyvec& sk)
    {
        polyvec_tobytes(r, sk);
    }

    /*************************************************
    * Name:        pack_pk
    *
    * Description: Serialize the public key as concatenation of the
    *              serialized vector of polynomials pk
    *              and the public seed used to generate the matrix A.
    *
    * Arguments:   uint8_t *r: pointer to the output serialized public key
    *              polyvec *pk: pointer to the input public-key polyvec
    *              const uint8_t *seed: pointer to the input public seed
    **************************************************/
    static void pack_pk(vector<uint8_t>& r,
        polyvec& pk,
        const vector<uint8_t>& seed)
    {
        size_t i;
        polyvec_tobytes(r, pk);
        for (i = 0; i < KYBER_SYMBYTES; i++)
            r[i + KYBER_POLYVECBYTES] = seed[i];
    }

    /*************************************************
    * Name:        indcpa_keypair
    *
    * Description: Generates public and private key for the CPA-secure
    *              public-key encryption scheme underlying Kyber
    *
    * Arguments:   - uint8_t *pk: pointer to output public key
    *                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
    *              - uint8_t *sk: pointer to output private key
                                  (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
    **************************************************/
    void indcpa_keypair(vector<uint8_t>& pk,
        vector<uint8_t>& sk)
    {
        uint32_t i;
        vector<uint8_t> buf(2 * KYBER_SYMBYTES);
        const vector<uint8_t> publicseed(buf);
        const vector<uint8_t> noiseseed(buf.begin() + KYBER_SYMBYTES, buf.end());
        uint8_t nonce = 0;
        vector<polyvec> a(KYBER_K);
        polyvec e, pkpv, skpv;
        e.vec.resize(KYBER_K);
        pkpv.vec.resize(KYBER_K);
        skpv.vec.resize(KYBER_K);
        for (i = 0; i < KYBER_K; i++) {
            e.vec[i].coeffs.resize(KYBER_N);
            pkpv.vec[i].coeffs.resize(KYBER_N);
            skpv.vec[i].coeffs.resize(KYBER_N);
        }

        randombytes(buf, KYBER_SYMBYTES);
        hash_g(buf, buf, KYBER_SYMBYTES);

        gen_a(a, publicseed);
        buf = publicseed;

        for (i = 0; i < KYBER_K; i++) {
            poly_getnoise_eta1(skpv.vec[i], noiseseed, nonce++);
            buf.insert(buf.begin() + KYBER_SYMBYTES, noiseseed.begin(), noiseseed.end());
            buf.resize(KYBER_SYMBYTES + noiseseed.size());
        }
        for (i = 0; i < KYBER_K; i++) {
            buf.insert(buf.begin() + KYBER_SYMBYTES, noiseseed.begin(), noiseseed.end());
            buf.resize(KYBER_SYMBYTES + noiseseed.size());
            poly_getnoise_eta1(e.vec[i], noiseseed, nonce++);
        }

        polyvec_ntt(skpv);
        polyvec_ntt(e);

        // matrix-vector multiplication
        for (i = 0; i < KYBER_K; i++) {
            polyvec_basemul_acc_montgomery(pkpv.vec[i], a[i], skpv);
            poly_tomont(pkpv.vec[i]);
        }

        polyvec_add(pkpv, pkpv, e);
        polyvec_reduce(pkpv);

        pack_sk(sk, skpv);
        pack_pk(pk, pkpv, publicseed);
        buf = publicseed;
    }

    /*************************************************
    * Name:        crypto_kem_keypair
    *
    * Description: Generates public and private key
    *              for CCA-secure Kyber key encapsulation mechanism
    *
    * Arguments:   - uint8_t *pk: pointer to output public key
    *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
    *              - uint8_t *sk: pointer to output private key
    *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
    *
    * Returns 0 (success)
    **************************************************/
    uint32_t crypto_kem_keypair(vector<uint8_t>& pk,
        vector<uint8_t>& sk)
    {
        size_t i;
        CrystalsKyber::indcpa_keypair(pk, sk);
        for (i = 0; i < KYBER_INDCPA_PUBLICKEYBYTES; i++)
            sk[i + KYBER_INDCPA_SECRETKEYBYTES] = pk[i];
        vector<uint8_t> copy(sk.begin() + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, sk.end());
        hash_h(copy, pk, KYBER_PUBLICKEYBYTES);
        sk.insert(sk.begin() + KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES, copy.begin(), copy.end());
        sk.resize(KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + copy.size());
        /* Value z for pseudo-random output on reject */
        copy.clear();
        copy.insert(copy.begin(), sk.begin() + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, sk.end());
        randombytes(copy, KYBER_SYMBYTES);
        sk.insert(sk.begin() + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, copy.begin(), copy.end());
        sk.resize(KYBER_SECRETKEYBYTES - KYBER_SYMBYTES + copy.size());
        return 0;
    }

    /*************************************************
    * Name:        pack_ciphertext
    *
    * Description: Serialize the ciphertext as concatenation of the
    *              compressed and serialized vector of polynomials b
    *              and the compressed and serialized polynomial v
    *
    * Arguments:   uint8_t *r: pointer to the output serialized ciphertext
    *              poly *pk: pointer to the input vector of polynomials b
    *              poly *v: pointer to the input polynomial v
    **************************************************/
    static void pack_ciphertext(vector<uint8_t>& r, polyvec& b, poly& v)
    {
        polyvec_compress(r, b);
        vector<uint8_t> copy(r.begin() + KYBER_POLYVECCOMPRESSEDBYTES, r.end());
        poly_compress(copy, v);
        r.insert(r.begin() + KYBER_POLYVECCOMPRESSEDBYTES, copy.begin(), copy.end());
        r.resize(KYBER_POLYVECCOMPRESSEDBYTES + copy.size());
    }

    /*************************************************
    * Name:        unpack_pk
    *
    * Description: De-serialize public key from a byte array;
    *              approximate inverse of pack_pk
    *
    * Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
    *              - uint8_t *seed: pointer to output seed to generate matrix A
    *              - const uint8_t *packedpk: pointer to input serialized public key
    **************************************************/
    static void unpack_pk(polyvec& pk,
        vector<uint8_t>& seed,
        vector<uint8_t>& packedpk)
    {
        size_t i;
        polyvec_frombytes(pk, packedpk);
        for (i = 0; i < KYBER_SYMBYTES; i++)
            seed[i] = packedpk[i + KYBER_POLYVECBYTES];
    }

    /*************************************************
    * Name:        indcpa_enc
    *
    * Description: Encryption function of the CPA-secure
    *              public-key encryption scheme underlying Kyber.
    *
    * Arguments:   - uint8_t *c: pointer to output ciphertext
    *                            (of length KYBER_INDCPA_BYTES bytes)
    *              - const uint8_t *m: pointer to input message
    *                                  (of length KYBER_INDCPA_MSGBYTES bytes)
    *              - const uint8_t *pk: pointer to input public key
    *                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
    *              - const uint8_t *coins: pointer to input random coins used as seed
    *                                      (of length KYBER_SYMBYTES) to deterministically
    *                                      generate all randomness
    **************************************************/
    void indcpa_enc(vector<uint8_t>& c,
        const vector<uint8_t>& m,
        vector<uint8_t>& pk,
        const vector<uint8_t>& coins)
    {
        uint32_t i;
        vector<uint8_t> seed(KYBER_SYMBYTES);
        uint8_t nonce = 0;
        polyvec sp, pkpv, ep, b;
        sp.vec.resize(KYBER_K);
        pkpv.vec.resize(KYBER_K);
        ep.vec.resize(KYBER_K);
        b.vec.resize(KYBER_K);
        vector<polyvec> at(KYBER_K);
        for (i = 0; i < KYBER_K; i++) {
            sp.vec[i].coeffs.resize(KYBER_N);
            pkpv.vec[i].coeffs.resize(KYBER_N);
            ep.vec[i].coeffs.resize(KYBER_N);
            b.vec[i].coeffs.resize(KYBER_N);
            at[i].vec.resize(KYBER_K);
            for (uint32_t j = 0; j < KYBER_K; j++) {
                at[i].vec[j].coeffs.resize(KYBER_N);
            }
        }
        poly v, k, epp;
        v.coeffs.resize(KYBER_N);
        k.coeffs.resize(KYBER_N);
        epp.coeffs.resize(KYBER_N);

        unpack_pk(pkpv, seed, pk);
        poly_frommsg(k, m);
        gen_at(at, seed);

        for (i = 0; i < KYBER_K; i++) {
            poly_getnoise_eta1(sp.vec[i], coins, nonce++);
        }
        for (i = 0; i < KYBER_K; i++) {
            poly_getnoise_eta2(ep.vec[i], coins, nonce++);
        }
        poly_getnoise_eta2(epp, coins, nonce++);

        polyvec_ntt(sp);

        // matrix-vector multiplication
        for (i = 0; i < KYBER_K; i++)
            polyvec_basemul_acc_montgomery(b.vec[i], at[i], sp);

        polyvec_basemul_acc_montgomery(v, pkpv, sp);

        polyvec_invntt_tomont(b);
        poly_invntt_tomont(v);

        polyvec_add(b, b, ep);
        poly_add(v, v, epp);
        poly_add(v, v, k);
        polyvec_reduce(b);
        poly_reduce(v);

        pack_ciphertext(c, b, v);
    }

    /*************************************************
    * Name:        crypto_kem_enc
    *
    * Description: Generates cipher text and shared
    *              secret for given public key
    *
    * Arguments:   - uint8_t *ct: pointer to output cipher text
    *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
    *              - uint8_t *ss: pointer to output shared secret
    *                (an already allocated array of KYBER_SSBYTES bytes)
    *              - const uint8_t *pk: pointer to input public key
    *                (an already allocated array of KYBER_PUBLICKEYBYTES bytes)
    *
    * Returns 0 (success)
    **************************************************/
    uint32_t crypto_kem_enc(vector<uint8_t>& ct,
        vector<uint8_t>& ss,
        vector<uint8_t>& pk)
    {
        vector<uint8_t> buf(2 * KYBER_SYMBYTES);
        /* Will contain key, coins */
        vector<uint8_t> kr(2 * KYBER_SYMBYTES);

        randombytes(buf, KYBER_SYMBYTES);
        /* Don't release system RNG output */
        hash_h(buf, buf, KYBER_SYMBYTES);

        /* Multitarget countermeasure for coins + contributory KEM */
        vector<uint8_t> copy(buf.begin() + KYBER_SYMBYTES, buf.end());
        hash_h(copy, pk, KYBER_PUBLICKEYBYTES);
        buf.insert(buf.begin() + KYBER_SYMBYTES, copy.begin(), copy.end());
        buf.resize(KYBER_SYMBYTES + copy.size());
        hash_g(kr, buf, 2 * KYBER_SYMBYTES);

        /* coins are in kr+KYBER_SYMBYTES */
        copy.clear();
        copy.insert(copy.begin(), kr.begin() + KYBER_SYMBYTES, kr.end());
        CrystalsKyber::indcpa_enc(ct, buf, pk, copy);
        kr.insert(kr.begin() + KYBER_SYMBYTES, copy.begin(), copy.end());
        kr.resize(KYBER_SYMBYTES + copy.size());

        /* overwrite coins in kr with H(c) */
        copy.clear();
        copy.insert(copy.begin(), kr.begin() + KYBER_SYMBYTES, kr.end());
        hash_h(copy, ct, KYBER_CIPHERTEXTBYTES);
        kr.insert(kr.begin() + KYBER_SYMBYTES, copy.begin(), copy.end());
        kr.resize(KYBER_SYMBYTES + copy.size());
        /* hash concatenation of pre-k and H(c) to k */
        kdf(ss, kr, 2 * KYBER_SYMBYTES);
        return 0;
    }

    /*************************************************
    * Name:        unpack_ciphertext
    *
    * Description: De-serialize and decompress ciphertext from a byte array;
    *              approximate inverse of pack_ciphertext
    *
    * Arguments:   - polyvec *b: pointer to the output vector of polynomials b
    *              - poly *v: pointer to the output polynomial v
    *              - const uint8_t *c: pointer to the input serialized ciphertext
    **************************************************/
    static void unpack_ciphertext(polyvec& b, poly& v, vector<uint8_t>& c)
    {
        polyvec_decompress(b, c);
        vector<uint8_t> copy(c.begin() + KYBER_POLYVECCOMPRESSEDBYTES, c.end());
        poly_decompress(v, copy);
        c.insert(c.begin() + KYBER_POLYVECCOMPRESSEDBYTES, copy.begin(), copy.end());
        c.resize(KYBER_POLYVECCOMPRESSEDBYTES + copy.size());
    }

    /*************************************************
    * Name:        unpack_sk
    *
    * Description: De-serialize the secret key; inverse of pack_sk
    *
    * Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
    *              - const uint8_t *packedsk: pointer to input serialized secret key
    **************************************************/
    static void unpack_sk(polyvec& sk, vector<uint8_t>& packedsk)
    {
        polyvec_frombytes(sk, packedsk);
    }

    /*************************************************
    * Name:        indcpa_dec
    *
    * Description: Decryption function of the CPA-secure
    *              public-key encryption scheme underlying Kyber.
    *
    * Arguments:   - uint8_t *m: pointer to output decrypted message
    *                            (of length KYBER_INDCPA_MSGBYTES)
    *              - const uint8_t *c: pointer to input ciphertext
    *                                  (of length KYBER_INDCPA_BYTES)
    *              - const uint8_t *sk: pointer to input secret key
    *                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
    **************************************************/
    void indcpa_dec(vector<uint8_t>& m,
        vector<uint8_t>& c,
        vector<uint8_t>& sk)
    {
        polyvec b, skpv;
        b.vec.resize(KYBER_K);
        skpv.vec.resize(KYBER_K);
        for (uint32_t i = 0; i < KYBER_K; i++) {
            b.vec[i].coeffs.resize(KYBER_N);
            skpv.vec[i].coeffs.resize(KYBER_N);
        }
        poly v, mp;
        v.coeffs.resize(KYBER_N);
        mp.coeffs.resize(KYBER_N);

        unpack_ciphertext(b, v, c);
        unpack_sk(skpv, sk);

        polyvec_ntt(b);
        polyvec_basemul_acc_montgomery(mp, skpv, b);
        poly_invntt_tomont(mp);

        poly_sub(mp, v, mp);
        poly_reduce(mp);

        poly_tomsg(m, mp);
    }

    /*************************************************
    * Name:        crypto_kem_dec
    *
    * Description: Generates shared secret for given
    *              cipher text and private key
    *
    * Arguments:   - uint8_t *ss: pointer to output shared secret
    *                (an already allocated array of KYBER_SSBYTES bytes)
    *              - const uint8_t *ct: pointer to input cipher text
    *                (an already allocated array of KYBER_CIPHERTEXTBYTES bytes)
    *              - const uint8_t *sk: pointer to input private key
    *                (an already allocated array of KYBER_SECRETKEYBYTES bytes)
    *
    * Returns 0.
    *
    * On failure, ss will contain a pseudo-random value.
    **************************************************/
    uint32_t crypto_kem_dec(vector<uint8_t>& ss,
        vector<uint8_t>& ct,
        vector<uint8_t>& sk)
    {
        size_t i;
        uint32_t fail;
        vector<uint8_t> buf(2 * KYBER_SYMBYTES);
        /* Will contain key, coins */
        vector<uint8_t> kr(2 * KYBER_SYMBYTES);
        vector<uint8_t> cmp(KYBER_CIPHERTEXTBYTES);
        vector<uint8_t> pk(sk.begin() + KYBER_INDCPA_SECRETKEYBYTES, sk.end());

        CrystalsKyber::indcpa_dec(buf, ct, sk);

        /* Multitarget countermeasure for coins + contributory KEM */
        for (i = 0; i < KYBER_SYMBYTES; i++)
            buf[KYBER_SYMBYTES + i] = sk[KYBER_SECRETKEYBYTES - 2 * KYBER_SYMBYTES + i];
        hash_g(kr, buf, 2 * KYBER_SYMBYTES);

        /* coins are in kr+KYBER_SYMBYTES */
        vector<uint8_t> copy(kr.begin() + KYBER_SYMBYTES, kr.end());
        CrystalsKyber::indcpa_enc(cmp, buf, pk, copy);
        sk.insert(sk.begin() + KYBER_INDCPA_SECRETKEYBYTES, pk.begin(), pk.end());
        sk.resize(KYBER_INDCPA_SECRETKEYBYTES + pk.size());
        kr.insert(kr.begin() + KYBER_SYMBYTES, copy.begin(), copy.end());
        kr.resize(KYBER_SYMBYTES + copy.size());

        fail = verify(ct, cmp, KYBER_CIPHERTEXTBYTES);

        /* overwrite coins in kr with H(c) */
        copy.clear();
        copy.insert(copy.begin(), kr.begin() + KYBER_SYMBYTES, kr.end());
        hash_h(copy, ct, KYBER_CIPHERTEXTBYTES);
        kr.insert(kr.begin() + KYBER_SYMBYTES, copy.begin(), copy.end());
        kr.resize(KYBER_SYMBYTES + copy.size());

        /* Overwrite pre-k with z on re-encryption failure */
        copy.clear();
        copy.insert(copy.begin(), sk.begin() + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, sk.end());
        cmov(kr, copy, KYBER_SYMBYTES, fail);
        sk.insert(sk.begin() + KYBER_SECRETKEYBYTES - KYBER_SYMBYTES, copy.begin(), copy.end());
        sk.resize(KYBER_SECRETKEYBYTES - KYBER_SYMBYTES + copy.size());

        /* hash concatenation of pre-k and H(c) to k */
        kdf(ss, kr, 2 * KYBER_SYMBYTES);
        return 0;
    }

}
