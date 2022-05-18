#ifndef SABER_H
#define SABER_H

#include "SaberUtils.hpp"

#define KAT_SUCCESS          0
#define KAT_CRYPTO_FAILURE  -4
#define CRYPTO_BYTES 32

namespace Saber {

	void indcpa_kem_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);
	uint32_t crypto_kem_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

	void indcpa_kem_enc(const std::vector<uint8_t>& m, std::vector<uint8_t>& seed_sp, std::vector<uint8_t>& pk, std::vector<uint8_t>& ciphertext);
	uint32_t crypto_kem_enc(std::vector<uint8_t>& ct, std::vector<uint8_t>& ss, std::vector<uint8_t>& pk);

	void indcpa_kem_dec(std::vector<uint8_t>& sk, std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& m);
	uint32_t crypto_kem_dec(std::vector<uint8_t>& ss, std::vector<uint8_t>& ct, std::vector<uint8_t>& sk);

}

#endif