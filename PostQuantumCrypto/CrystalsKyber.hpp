#ifndef CRYSTALS_KYBER_H
#define CRYSTALS_KYBER_H

#include "CrystalsKyberUtils.hpp"

#define KAT_SUCCESS          0
#define KAT_CRYPTO_FAILURE  -4

namespace CrystalsKyber {

	void indcpa_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);
	uint32_t crypto_kem_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

	void indcpa_enc(std::vector<uint8_t>& c, const std::vector<uint8_t>& m, std::vector<uint8_t>& pk, const std::vector<uint8_t>& coins);
	uint32_t crypto_kem_enc(std::vector<uint8_t>& ct, std::vector<uint8_t>& ss, std::vector<uint8_t>& pk);

	void indcpa_dec(std::vector<uint8_t>& m, std::vector<uint8_t>& c, std::vector<uint8_t>& sk);
	uint32_t crypto_kem_dec(std::vector<uint8_t>& ss, std::vector<uint8_t>& ct, std::vector<uint8_t>& sk);

}
#endif