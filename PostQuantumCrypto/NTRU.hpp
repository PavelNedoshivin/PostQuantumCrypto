#ifndef NTRU_H
#define NTRU_H

#include "NTRUUtils.hpp"

#define KAT_SUCCESS          0
#define KAT_CRYPTO_FAILURE  -4
#define CRYPTO_SECRETKEYBYTES 935
#define CRYPTO_PUBLICKEYBYTES 699
#define CRYPTO_CIPHERTEXTBYTES 699
#define CRYPTO_BYTES 32

namespace NTRU {

	void owcpa_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk, std::vector<uint8_t>& seed);
	uint32_t crypto_kem_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

	void owcpa_enc(std::vector<uint8_t>& c, const poly& r, const poly& m, const std::vector<uint8_t>& pk);
	uint32_t crypto_kem_enc(std::vector<uint8_t>& c, std::vector<uint8_t>& k, const std::vector<uint8_t>& pk);

	uint32_t owcpa_dec(std::vector<uint8_t>& rm, const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& secretkey);
	uint32_t crypto_kem_dec(std::vector<uint8_t>& k, const std::vector<uint8_t>& c, std::vector<uint8_t>& sk);

}

#endif