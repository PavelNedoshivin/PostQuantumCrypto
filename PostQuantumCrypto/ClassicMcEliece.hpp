#ifndef CLASSIC_MCELIECE_H
#define CLASSIC_MCELIECE_H

#include "ClassicMcElieceUtils.hpp"
#include "CrystalsKyberUtils.hpp"

#define crypto_kem_PUBLICKEYBYTES 261120
#define crypto_kem_SECRETKEYBYTES 6492
#define crypto_kem_CIPHERTEXTBYTES 128
#define crypto_kem_BYTES 32
#define KAT_CRYPTO_FAILURE  -4
#define KAT_SUCCESS          0

#define crypto_hash_32b(out,in,inlen) \
  CrystalsKyber::shake256(out,32,in,inlen)

#define shake(out,outlen,in,inlen) \
  CrystalsKyber::shake256(out,outlen,in,inlen)

namespace ClassicMcEliece {

	void encrypt(std::vector<uint8_t>& s, const std::vector<uint8_t>& pk, std::vector<uint8_t>& e);
	uint32_t crypto_kem_enc(std::vector<uint8_t>& c, std::vector<uint8_t>& key, const std::vector<uint8_t>& pk);

	uint32_t decrypt(std::vector<uint8_t>& e, std::vector<uint8_t>& sk, const std::vector<uint8_t>& c);
	uint32_t crypto_kem_dec(std::vector<uint8_t>& key, const std::vector<uint8_t>& c, std::vector<uint8_t>& sk);

	uint32_t pk_gen(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk, std::vector<uint32_t>& perm, std::vector<int16_t>& pi);
	uint32_t crypto_kem_keypair(std::vector<uint8_t>& pk, std::vector<uint8_t>& sk);

}

#endif