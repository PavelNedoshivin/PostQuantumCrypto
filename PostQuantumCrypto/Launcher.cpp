#include "Launcher.hpp"

#include <iostream>
#include <ctime>

using namespace std;

int runClassicMcEliece() {
	cout << "Classic McEliece" << endl;
	vector<uint8_t> pk(crypto_kem_PUBLICKEYBYTES);
	vector<uint8_t> sk(crypto_kem_SECRETKEYBYTES);
	clock_t start = clock();
	if (ClassicMcEliece::crypto_kem_keypair(pk, sk) != 0) {
		cout << "Failure in Keypair" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	clock_t end = clock();
	cout << "Keypair time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "pk = ";
	for (uint32_t i = 0; i < crypto_kem_PUBLICKEYBYTES; i++) {
		uint8_t val = pk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "sk = ";
	for (uint32_t i = 0; i < crypto_kem_SECRETKEYBYTES; i++) {
		uint8_t val = sk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ct(crypto_kem_CIPHERTEXTBYTES);
	vector<uint8_t> ss(crypto_kem_BYTES);
	start = clock();
	if (ClassicMcEliece::crypto_kem_enc(ct, ss, pk) != 0) {
		cout << "Failure in Encrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Encrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "ct = ";
	for (uint32_t i = 0; i < crypto_kem_CIPHERTEXTBYTES; i++) {
		uint8_t val = ct[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "ss = ";
	for (uint32_t i = 0; i < crypto_kem_BYTES; i++) {
		uint8_t val = ss[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ss1(crypto_kem_BYTES);
	start = clock();
	if (ClassicMcEliece::crypto_kem_dec(ss1, ct, sk) != 0) {
		cout << "Failure in Decrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Decrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	if (ss1 != ss) {
		cout << "Wrong result" << endl;
	}
	return KAT_SUCCESS;
}
int runCrystalsKyber() {
	cout << "Crystals Kyber" << endl;
	vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
	vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES);
	clock_t start = clock();
	if (CrystalsKyber::crypto_kem_keypair(pk, sk) != 0) {
		cout << "Failure in Keypair" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	clock_t end = clock();
	cout << "Keypair time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "pk = ";
	for (uint32_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
		uint8_t val = pk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "sk = ";
	for (uint32_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
		uint8_t val = sk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ct(CRYPTO_CIPHERTEXTBYTES);
	vector<uint8_t> ss(CRYPTO_BYTES);
	start = clock();
	if (CrystalsKyber::crypto_kem_enc(ct, ss, pk) != 0) {
		cout << "Failure in Encrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Encrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "ct = ";
	for (uint32_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
		uint8_t val = ct[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "ss = ";
	for (uint32_t i = 0; i < CRYPTO_BYTES; i++) {
		uint8_t val = ss[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ss1(CRYPTO_BYTES);
	start = clock();
	if (CrystalsKyber::crypto_kem_dec(ss1, ct, sk) != 0) {
		cout << "Failure in Decrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Decrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	if (ss1 != ss) {
		cout << "Wrong result" << endl;
	}
	return KAT_SUCCESS;
}
int runNTRU() {
	cout << "NTRU" << endl;
	vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
	vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES);
	clock_t start = clock();
	if (NTRU::crypto_kem_keypair(pk, sk) != 0) {
		cout << "Failure in Keypair" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	clock_t end = clock();
	cout << "Keypair time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "pk = ";
	for (uint32_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
		uint8_t val = pk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "sk = ";
	for (uint32_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
		uint8_t val = sk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ct(CRYPTO_CIPHERTEXTBYTES);
	vector<uint8_t> ss(CRYPTO_BYTES);
	start = clock();
	if (NTRU::crypto_kem_enc(ct, ss, pk) != 0) {
		cout << "Failure in Encrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Encrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "ct = ";
	for (uint32_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
		uint8_t val = ct[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "ss = ";
	for (uint32_t i = 0; i < CRYPTO_BYTES; i++) {
		uint8_t val = ss[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ss1(CRYPTO_BYTES);
	start = clock();
	if (NTRU::crypto_kem_dec(ss1, ct, sk) != 0) {
		cout << "Failure in Decrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Decrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	if (ss1 != ss) {
		cout << "Wrong result" << endl;
	}
	return KAT_SUCCESS;
}
int runSaber() {
	cout << "Saber" << endl;
	vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES);
	vector<uint8_t> sk(CRYPTO_SECRETKEYBYTES);
	clock_t start = clock();
	if (Saber::crypto_kem_keypair(pk, sk) != 0) {
		cout << "Failure in Keypair" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	clock_t end = clock();
	cout << "Keypair time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "pk = ";
	for (uint32_t i = 0; i < CRYPTO_PUBLICKEYBYTES; i++) {
		uint8_t val = pk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "sk = ";
	for (uint32_t i = 0; i < CRYPTO_SECRETKEYBYTES; i++) {
		uint8_t val = sk[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ct(CRYPTO_CIPHERTEXTBYTES);
	vector<uint8_t> ss(CRYPTO_BYTES);
	start = clock();
	if (Saber::crypto_kem_enc(ct, ss, pk) != 0) {
		cout << "Failure in Encrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Encrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	cout << "ct = ";
	for (uint32_t i = 0; i < CRYPTO_CIPHERTEXTBYTES; i++) {
		uint8_t val = ct[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	cout << "ss = ";
	for (uint32_t i = 0; i < CRYPTO_BYTES; i++) {
		uint8_t val = ss[i];
		vector<uint8_t> binStr;
		while (val > 0) {
			binStr.push_back(val % 2);
			val /= 2;
		}
		binStr.resize(8);
		reverse(binStr.begin(), binStr.end());
		for (uint32_t j = 0; j < 8; j++) {
			cout << static_cast<uint8_t>('0' + binStr[j]);
		}
	}
	cout << "\n";
	vector<uint8_t> ss1(CRYPTO_BYTES);
	start = clock();
	if (Saber::crypto_kem_dec(ss1, ct, sk) != 0) {
		cout << "Failure in Decrypt" << endl;
		return KAT_CRYPTO_FAILURE;
	}
	end = clock();
	cout << "Decrypt time: " << (static_cast<double>(end - start) / CLOCKS_PER_SEC) << endl;
	if (ss1 != ss) {
		cout << "Wrong result" << endl;
	}
	return KAT_SUCCESS;
}