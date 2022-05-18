#include "Saber.hpp"

using namespace std;

namespace Saber {

    void indcpa_kem_keypair(vector<uint8_t>& pk, vector<uint8_t>& sk)
    {
        vector<vector<vector<uint16_t>>> A(SABER_L);
        vector<vector<uint16_t>> s(SABER_L);
        vector<vector<uint16_t>> b(SABER_L);
        for (uint32_t i = 0; i < SABER_L; i++) {
            A[i].resize(SABER_L);
            s[i].resize(SABER_N);
            b[i].resize(SABER_N);
            for (uint32_t j = 0; j < SABER_L; j++) {
                A[i][j].resize(SABER_N);
            }
        }

        vector<uint8_t> seed_A(SABER_SEEDBYTES);
        vector<uint8_t> seed_s(SABER_NOISE_SEEDBYTES);
        uint32_t i, j;

        randombytes(seed_A, SABER_SEEDBYTES);
        shake128(seed_A, SABER_SEEDBYTES, seed_A, SABER_SEEDBYTES); // for not revealing system RNG state
        randombytes(seed_s, SABER_NOISE_SEEDBYTES);

        GenMatrix(A, seed_A);
        GenSecret(s, seed_s);
        MatrixVectorMul(A, s, b, 1);

        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_N; j++)
            {
                b[i][j] = (b[i][j] + h1) >> (SABER_EQ - SABER_EP);
            }
        }

        POLVECq2BS(sk, s);
        POLVECp2BS(pk, b);
        pk.insert(pk.begin() + SABER_POLYVECCOMPRESSEDBYTES, seed_A.begin(), seed_A.end());
        pk.resize(SABER_POLYVECCOMPRESSEDBYTES + seed_A.size());
    }

    uint32_t crypto_kem_keypair(vector<uint8_t>& pk, vector<uint8_t>& sk)
    {
        uint32_t i;

        indcpa_kem_keypair(pk, sk); // sk[0:SABER_INDCPA_SECRETKEYBYTES-1] <-- sk
        for (i = 0; i < SABER_INDCPA_PUBLICKEYBYTES; i++)
            sk[i + SABER_INDCPA_SECRETKEYBYTES] = pk[i]; // sk[SABER_INDCPA_SECRETKEYBYTES:SABER_INDCPA_SECRETKEYBYTES+SABER_INDCPA_SECRETKEYBYTES-1] <-- pk

        vector<uint8_t> copy(sk.begin() + SABER_SECRETKEYBYTES - 64, sk.end());
        sha3_256(copy, pk, SABER_INDCPA_PUBLICKEYBYTES); // Then hash(pk) is appended.
        sk.insert(sk.begin() + SABER_SECRETKEYBYTES - 64, copy.begin(), copy.end());
        sk.resize(SABER_SECRETKEYBYTES - 64 + copy.size());

        copy.clear();
        copy.insert(copy.begin(), sk.begin() + SABER_SECRETKEYBYTES - SABER_KEYBYTES, sk.end());
        randombytes(copy, SABER_KEYBYTES); // Remaining part of sk contains a pseudo-random number.
                                                                                 // This is output when check in crypto_kem_dec() fails.
        sk.insert(sk.begin() + SABER_SECRETKEYBYTES - SABER_KEYBYTES, copy.begin(), copy.end());
        sk.resize(SABER_SECRETKEYBYTES - SABER_KEYBYTES + copy.size());
        return (0);
    }

    void indcpa_kem_enc(const vector<uint8_t>& m, vector<uint8_t>& seed_sp, vector<uint8_t>& pk, vector<uint8_t>& ciphertext)
    {
        vector<vector<vector<uint16_t>>> A(SABER_L);
        vector<vector<uint16_t>> sp(SABER_L);
        vector<vector<uint16_t>> bp(SABER_L);
        vector<vector<uint16_t>> b(SABER_L);
        for (uint32_t i = 0; i < SABER_L; i++) {
            A[i].resize(SABER_L);
            sp[i].resize(SABER_N);
            bp[i].resize(SABER_N);
            b[i].resize(SABER_N);
            for (uint32_t j = 0; j < SABER_L; j++) {
                A[i][j].resize(SABER_N);
            }
            for (uint32_t j = 0; j < SABER_N; j++) {
                bp[i][j] = 0;
            }
        }
        vector<uint16_t> vp(SABER_N);
        vector<uint16_t> mp(SABER_N);
        for (uint32_t i = 0; i < SABER_N; i++) {
            vp[i] = 0;
        }
        uint32_t i, j;
        vector<uint8_t> seed_A(pk.begin() + SABER_POLYVECCOMPRESSEDBYTES, pk.end());

        GenMatrix(A, seed_A);
        GenSecret(sp, seed_sp);
        MatrixVectorMul(A, sp, bp, 0);

        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_N; j++)
            {
                bp[i][j] = (bp[i][j] + h1) >> (SABER_EQ - SABER_EP);
            }
        }

        POLVECp2BS(ciphertext, bp);
        BS2POLVECp(pk, b);
        InnerProd(b, sp, vp);

        BS2POLmsg(m, mp);

        for (j = 0; j < SABER_N; j++)
        {
            vp[j] = (vp[j] - (mp[j] << (SABER_EP - 1)) + h1) >> (SABER_EP - SABER_ET);
        }

        vector<uint8_t> copy(ciphertext.begin() + SABER_POLYVECCOMPRESSEDBYTES, ciphertext.end());
        POLT2BS(copy, vp);
        ciphertext.insert(ciphertext.begin() + SABER_POLYVECCOMPRESSEDBYTES, copy.begin(), copy.end());
        ciphertext.resize(SABER_POLYVECCOMPRESSEDBYTES + copy.size());
    }

    uint32_t crypto_kem_enc(vector<uint8_t>& c, vector<uint8_t>& k, vector<uint8_t>& pk)
    {

        vector<uint8_t> kr(64); // Will contain key, coins
        vector<uint8_t> buf(64);

        randombytes(buf, 32);

        sha3_256(buf, buf, 32); // BUF[0:31] <-- random message (will be used as the key for client) Note: hash doesnot release system RNG output

        vector<uint8_t> copy(buf.begin() + 32, buf.end());
        sha3_256(copy, pk, SABER_INDCPA_PUBLICKEYBYTES); // BUF[32:63] <-- Hash(public key);  Multitarget countermeasure for coins + contributory KEM
        buf.insert(buf.begin() + 32, copy.begin(), copy.end());
        buf.resize(32 + copy.size());

        sha3_512(kr, buf, 64);               // kr[0:63] <-- Hash(buf[0:63]);
                                             // K^ <-- kr[0:31]
                                             // noiseseed (r) <-- kr[32:63];
        copy.clear();
        copy.insert(copy.begin(), kr.begin() + 32, kr.end());
        indcpa_kem_enc(buf, copy, pk, c); // buf[0:31] contains message; kr[32:63] contains randomness r;

        sha3_256(copy, c, SABER_BYTES_CCA_DEC);
        kr.insert(kr.begin() + 32, copy.begin(), copy.end());
        kr.resize(32 + copy.size());

        sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

        return (0);
    }

    void indcpa_kem_dec(vector<uint8_t>& sk, vector<uint8_t>& ciphertext, vector<uint8_t>& m)
    {
        vector<vector<uint16_t>> s(SABER_L);
        vector<vector<uint16_t>> b(SABER_L);
        for (uint32_t i = 0; i < SABER_L; i++) {
            s[i].resize(SABER_N);
            b[i].resize(SABER_N);
        }
        vector<uint16_t> v(SABER_N);
        for (uint32_t i = 0; i < SABER_N; i++) {
            v[i] = 0;
        }
        vector<uint16_t> cm(SABER_N);
        uint32_t i;

        BS2POLVECq(sk, s);
        BS2POLVECp(ciphertext, b);
        InnerProd(b, s, v);
        vector<uint8_t> copy(ciphertext.begin() + SABER_POLYVECCOMPRESSEDBYTES, ciphertext.end());
        BS2POLT(copy, cm);
        ciphertext.insert(ciphertext.begin() + SABER_POLYVECCOMPRESSEDBYTES, copy.begin(), copy.end());
        ciphertext.resize(SABER_POLYVECCOMPRESSEDBYTES + copy.size());

        for (i = 0; i < SABER_N; i++)
        {
            v[i] = (v[i] + h2 - (cm[i] << (SABER_EP - SABER_ET))) >> (SABER_EP - 1);
        }

        POLmsg2BS(m, v);
    }

    uint32_t crypto_kem_dec(vector<uint8_t>& k, vector<uint8_t>& c, vector<uint8_t>& sk)
    {
        uint32_t i, fail;
        vector<uint8_t> cmp(SABER_BYTES_CCA_DEC);
        vector<uint8_t> buf(64);
        vector<uint8_t> kr(64); // Will contain key, coins
        vector<uint8_t> pk(sk.begin() + SABER_INDCPA_SECRETKEYBYTES, sk.end());

        indcpa_kem_dec(sk, c, buf); // buf[0:31] <-- message

        // Multitarget countermeasure for coins + contributory KEM
        for (i = 0; i < 32; i++) // Save hash by storing h(pk) in sk
            buf[32 + i] = sk[SABER_SECRETKEYBYTES - 64 + i];

        sha3_512(kr, buf, 64);

        vector<uint8_t> copy(kr.begin() + 32, kr.end());
        indcpa_kem_enc(buf, copy, pk, cmp);

        fail = verify(c, cmp, SABER_BYTES_CCA_DEC);

        sha3_256(copy, c, SABER_BYTES_CCA_DEC); // overwrite coins in kr with h(c)
        kr.insert(kr.begin() + 32, copy.begin(), copy.end());
        kr.resize(32 + copy.size());
        copy.clear();
        copy.insert(copy.begin(), sk.begin() + SABER_SECRETKEYBYTES - SABER_KEYBYTES, sk.end());
        cmov(kr, copy, SABER_KEYBYTES, fail);
        sk.insert(sk.begin() + SABER_SECRETKEYBYTES - SABER_KEYBYTES, copy.begin(), copy.end());
        sk.resize(SABER_SECRETKEYBYTES - SABER_KEYBYTES + copy.size());

        sha3_256(k, kr, 64); // hash concatenation of pre-k and h(c) to k

        return (0);
    }

}
