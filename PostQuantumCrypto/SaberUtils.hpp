#ifndef SABER_UTILS_H
#define SABER_UTILS_H

#include <vector>

#define RNG_SUCCESS      0
#define SHAKE128_RATE 168
#define SHA3_256_RATE 136
#define SHA3_512_RATE 72
#define NROUNDS 24
#define KARATSUBA_N 64
#define SABER_L 2
#define SABER_ET 3
#define SABER_MU 10
#define SABER_N 256
#define SABER_EQ 13
#define SABER_EP 10
#define SABER_HASHBYTES 32
#define SABER_KEYBYTES 32
#define SABER_SEEDBYTES 32
#define SABER_NOISE_SEEDBYTES 32
#define SABER_POLYBYTES (SABER_EQ * SABER_N / 8)
#define SABER_POLYCOINBYTES (SABER_MU * SABER_N / 8)
#define SABER_POLYCOMPRESSEDBYTES (SABER_EP * SABER_N / 8)
#define SABER_POLYVECBYTES (SABER_L * SABER_POLYBYTES)
#define SABER_POLYVECCOMPRESSEDBYTES (SABER_L * SABER_POLYCOMPRESSEDBYTES)
#define SABER_INDCPA_SECRETKEYBYTES (SABER_POLYVECBYTES)
#define SABER_INDCPA_PUBLICKEYBYTES (SABER_POLYVECCOMPRESSEDBYTES + SABER_SEEDBYTES)
#define SABER_SCALEBYTES_KEM (SABER_ET * SABER_N / 8)
#define SABER_SECRETKEYBYTES (SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES)
#define SABER_BYTES_CCA_DEC (SABER_POLYVECCOMPRESSEDBYTES + SABER_SCALEBYTES_KEM)
#define CRYPTO_SECRETKEYBYTES (SABER_INDCPA_SECRETKEYBYTES + SABER_INDCPA_PUBLICKEYBYTES + SABER_HASHBYTES + SABER_KEYBYTES)
#define CRYPTO_PUBLICKEYBYTES (SABER_INDCPA_PUBLICKEYBYTES)
#define CRYPTO_CIPHERTEXTBYTES (SABER_POLYVECCOMPRESSEDBYTES + SABER_SCALEBYTES_KEM)
#define N_SB (SABER_N >> 2)
#define N_SB_RES (2*N_SB-1)

#define ROL(a, offset) ((a << offset) ^ (a >> (64 - offset)))
#define OVERFLOWING_MUL(X, Y) (static_cast<uint16_t>(static_cast<uint32_t>(X) * static_cast<uint32_t>(Y)))
#define h1 (1 << (SABER_EQ - SABER_EP - 1))
#define h2 ((1 << (SABER_EP - 2)) - (1 << (SABER_EP - SABER_ET - 1)) + (1 << (SABER_EQ - SABER_EP - 1)))

namespace Saber {

    typedef struct {
        std::vector<uint8_t>   Key;
        std::vector<uint8_t>   V;
        uint32_t             reseed_counter;
    } AES256_CTR_DRBG_struct;

    void AES256_CTR_DRBG_Update(std::vector<uint8_t>& provided_data, std::vector<uint8_t>& Key, std::vector<uint8_t>& V);
    uint32_t randombytes(std::vector<uint8_t>& x, uint64_t xlen);
    void shake128(std::vector<uint8_t>& output, uint64_t outlen, std::vector<uint8_t>& input, uint64_t inlen);
    void BS2POLVECq(std::vector<uint8_t>& bytes, std::vector<std::vector<uint16_t>>& data);
    void GenMatrix(std::vector<std::vector<std::vector<uint16_t>>>& a, std::vector<uint8_t>& seed);
    void cbd(std::vector<uint16_t>& s, std::vector<uint8_t>& buf);
    void GenSecret(std::vector<std::vector<uint16_t>>& s, std::vector<uint8_t>& seed);
    void poly_mul_acc(const std::vector<uint16_t>& a, const std::vector<uint16_t>& b, std::vector<uint16_t>& res);
    void MatrixVectorMul(const std::vector<std::vector<std::vector<uint16_t>>>& a, const std::vector<std::vector<uint16_t>>& s, std::vector<std::vector<uint16_t>>& res, int16_t transpose);
    void POLVECq2BS(std::vector<uint8_t>& bytes, const std::vector<std::vector<uint16_t>>& data);
    void POLVECp2BS(std::vector<uint8_t>& bytes, const std::vector<std::vector<uint16_t>>& data);
    void sha3_256(std::vector<uint8_t>& output, std::vector<uint8_t>& input, uint64_t inlen);
    void BS2POLVECp(std::vector<uint8_t>& bytes, std::vector<std::vector<uint16_t>>& data);
    void InnerProd(const std::vector<std::vector<uint16_t>>& b, const std::vector<std::vector<uint16_t>>& s, std::vector<uint16_t>& res);
    void BS2POLmsg(const std::vector<uint8_t>& bytes, std::vector<uint16_t>& data);
    void POLT2BS(std::vector<uint8_t>& bytes, const std::vector<uint16_t>& data);
    void sha3_512(std::vector<uint8_t>& output, std::vector<uint8_t>& input, uint64_t inlen);
    void BS2POLT(const std::vector<uint8_t>& bytes, std::vector<uint16_t>& data);
    void POLmsg2BS(std::vector<uint8_t>& bytes, const std::vector<uint16_t>& data);
    uint32_t verify(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b, size_t len);
    void cmov(std::vector<uint8_t>& r, const std::vector<uint8_t>& x, size_t len, uint8_t b);

}

#endif