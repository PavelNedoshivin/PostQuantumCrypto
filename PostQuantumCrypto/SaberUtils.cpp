#include "SaberUtils.hpp"

using namespace std;

namespace Saber {

    AES256_CTR_DRBG_struct  DRBG_ctx;

    void
        AES256_CTR_DRBG_Update(vector<uint8_t>& provided_data,
            vector<uint8_t>& Key,
            vector<uint8_t>& V)
    {
        vector<uint8_t>   temp(48);

        for (int i = 0; i < 3; i++) {
            //increment V
            for (int j = 15; j >= 0; j--) {
                if (V[j] == 0xff)
                    V[j] = 0x00;
                else {
                    V[j]++;
                    break;
                }
            }
        }
        if (!provided_data.empty())
            for (int i = 0; i < 48; i++)
                temp[i] ^= provided_data[i];
        Key.insert(Key.begin(), temp.begin(), temp.begin() + 32);
        Key.resize(32);
        V.insert(V.begin(), temp.begin() + 32, temp.begin() + 48);
        V.resize(16);
    }

    uint32_t randombytes(vector<uint8_t>& x, uint64_t xlen)
    {
        DRBG_ctx.Key.resize(32);
        DRBG_ctx.V.resize(16);
        vector<uint8_t>   block(16);
        uint32_t             i = 0;

        while (xlen > 0) {
            //increment V
            for (int j = 15; j >= 0; j--) {
                if (DRBG_ctx.V[j] == 0xff)
                    DRBG_ctx.V[j] = 0x00;
                else {
                    DRBG_ctx.V[j]++;
                    break;
                }
            }
            if (xlen > 15) {
                x.insert(x.begin() + i, block.begin(), block.begin() + 16);
                x.resize(i + 16);
                i += 16;
                xlen -= 16;
            }
            else {
                x.insert(x.begin() + i, block.begin(), block.begin() + xlen);
                x.resize(i + xlen);
                xlen = 0;
            }
        }
        vector<uint8_t> data;
        AES256_CTR_DRBG_Update(data, DRBG_ctx.Key, DRBG_ctx.V);
        DRBG_ctx.reseed_counter++;

        return RNG_SUCCESS;
    }

    static uint64_t load64(const vector<uint8_t>& x)
    {
        uint64_t r = 0, i;

        for (i = 0; i < 8; ++i)
        {
            r |= static_cast<unsigned long long>(x[i]) << 8 * i;
        }
        return r;
    }

    static const uint64_t KeccakF_RoundConstants[NROUNDS] =
    {
        static_cast<uint64_t>(0x0000000000000001ULL),
        static_cast<uint64_t>(0x0000000000008082ULL),
        static_cast<uint64_t>(0x800000000000808aULL),
        static_cast<uint64_t>(0x8000000080008000ULL),
        static_cast<uint64_t>(0x000000000000808bULL),
        static_cast<uint64_t>(0x0000000080000001ULL),
        static_cast<uint64_t>(0x8000000080008081ULL),
        static_cast<uint64_t>(0x8000000000008009ULL),
        static_cast<uint64_t>(0x000000000000008aULL),
        static_cast<uint64_t>(0x0000000000000088ULL),
        static_cast<uint64_t>(0x0000000080008009ULL),
        static_cast<uint64_t>(0x000000008000000aULL),
        static_cast<uint64_t>(0x000000008000808bULL),
        static_cast<uint64_t>(0x800000000000008bULL),
        static_cast<uint64_t>(0x8000000000008089ULL),
        static_cast<uint64_t>(0x8000000000008003ULL),
        static_cast<uint64_t>(0x8000000000008002ULL),
        static_cast<uint64_t>(0x8000000000000080ULL),
        static_cast<uint64_t>(0x000000000000800aULL),
        static_cast<uint64_t>(0x800000008000000aULL),
        static_cast<uint64_t>(0x8000000080008081ULL),
        static_cast<uint64_t>(0x8000000000008080ULL),
        static_cast<uint64_t>(0x0000000080000001ULL),
        static_cast<uint64_t>(0x8000000080008008ULL) };

    static void KeccakF1600_StatePermute(vector<uint64_t>& state)
    {
        uint32_t round;

        uint64_t Aba, Abe, Abi, Abo, Abu;
        uint64_t Aga, Age, Agi, Ago, Agu;
        uint64_t Aka, Ake, Aki, Ako, Aku;
        uint64_t Ama, Ame, Ami, Amo, Amu;
        uint64_t Asa, Ase, Asi, Aso, Asu;
        uint64_t BCa, BCe, BCi, BCo, BCu;
        uint64_t Da, De, Di, Do, Du;
        uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        uint64_t Ega, Ege, Egi, Ego, Egu;
        uint64_t Eka, Eke, Eki, Eko, Eku;
        uint64_t Ema, Eme, Emi, Emo, Emu;
        uint64_t Esa, Ese, Esi, Eso, Esu;

        //copyFromState(A, state)
        Aba = state[0];
        Abe = state[1];
        Abi = state[2];
        Abo = state[3];
        Abu = state[4];
        Aga = state[5];
        Age = state[6];
        Agi = state[7];
        Ago = state[8];
        Agu = state[9];
        Aka = state[10];
        Ake = state[11];
        Aki = state[12];
        Ako = state[13];
        Aku = state[14];
        Ama = state[15];
        Ame = state[16];
        Ami = state[17];
        Amo = state[18];
        Amu = state[19];
        Asa = state[20];
        Ase = state[21];
        Asi = state[22];
        Aso = state[23];
        Asu = state[24];

        for (round = 0; round < NROUNDS; round += 2)
        {
            //    prepareTheta
            BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
            BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
            BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
            BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
            BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

            //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
            Da = BCu ^ ROL(BCe, 1);
            De = BCa ^ ROL(BCi, 1);
            Di = BCe ^ ROL(BCo, 1);
            Do = BCi ^ ROL(BCu, 1);
            Du = BCo ^ ROL(BCa, 1);

            Aba ^= Da;
            BCa = Aba;
            Age ^= De;
            BCe = ROL(Age, 44);
            Aki ^= Di;
            BCi = ROL(Aki, 43);
            Amo ^= Do;
            BCo = ROL(Amo, 21);
            Asu ^= Du;
            BCu = ROL(Asu, 14);
            Eba = BCa ^ ((~BCe) & BCi);
            Eba ^= static_cast<uint64_t>(KeccakF_RoundConstants[round]);
            Ebe = BCe ^ ((~BCi) & BCo);
            Ebi = BCi ^ ((~BCo) & BCu);
            Ebo = BCo ^ ((~BCu) & BCa);
            Ebu = BCu ^ ((~BCa) & BCe);

            Abo ^= Do;
            BCa = ROL(Abo, 28);
            Agu ^= Du;
            BCe = ROL(Agu, 20);
            Aka ^= Da;
            BCi = ROL(Aka, 3);
            Ame ^= De;
            BCo = ROL(Ame, 45);
            Asi ^= Di;
            BCu = ROL(Asi, 61);
            Ega = BCa ^ ((~BCe) & BCi);
            Ege = BCe ^ ((~BCi) & BCo);
            Egi = BCi ^ ((~BCo) & BCu);
            Ego = BCo ^ ((~BCu) & BCa);
            Egu = BCu ^ ((~BCa) & BCe);

            Abe ^= De;
            BCa = ROL(Abe, 1);
            Agi ^= Di;
            BCe = ROL(Agi, 6);
            Ako ^= Do;
            BCi = ROL(Ako, 25);
            Amu ^= Du;
            BCo = ROL(Amu, 8);
            Asa ^= Da;
            BCu = ROL(Asa, 18);
            Eka = BCa ^ ((~BCe) & BCi);
            Eke = BCe ^ ((~BCi) & BCo);
            Eki = BCi ^ ((~BCo) & BCu);
            Eko = BCo ^ ((~BCu) & BCa);
            Eku = BCu ^ ((~BCa) & BCe);

            Abu ^= Du;
            BCa = ROL(Abu, 27);
            Aga ^= Da;
            BCe = ROL(Aga, 36);
            Ake ^= De;
            BCi = ROL(Ake, 10);
            Ami ^= Di;
            BCo = ROL(Ami, 15);
            Aso ^= Do;
            BCu = ROL(Aso, 56);
            Ema = BCa ^ ((~BCe) & BCi);
            Eme = BCe ^ ((~BCi) & BCo);
            Emi = BCi ^ ((~BCo) & BCu);
            Emo = BCo ^ ((~BCu) & BCa);
            Emu = BCu ^ ((~BCa) & BCe);

            Abi ^= Di;
            BCa = ROL(Abi, 62);
            Ago ^= Do;
            BCe = ROL(Ago, 55);
            Aku ^= Du;
            BCi = ROL(Aku, 39);
            Ama ^= Da;
            BCo = ROL(Ama, 41);
            Ase ^= De;
            BCu = ROL(Ase, 2);
            Esa = BCa ^ ((~BCe) & BCi);
            Ese = BCe ^ ((~BCi) & BCo);
            Esi = BCi ^ ((~BCo) & BCu);
            Eso = BCo ^ ((~BCu) & BCa);
            Esu = BCu ^ ((~BCa) & BCe);

            //    prepareTheta
            BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
            BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
            BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
            BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
            BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;

            //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
            Da = BCu ^ ROL(BCe, 1);
            De = BCa ^ ROL(BCi, 1);
            Di = BCe ^ ROL(BCo, 1);
            Do = BCi ^ ROL(BCu, 1);
            Du = BCo ^ ROL(BCa, 1);

            Eba ^= Da;
            BCa = Eba;
            Ege ^= De;
            BCe = ROL(Ege, 44);
            Eki ^= Di;
            BCi = ROL(Eki, 43);
            Emo ^= Do;
            BCo = ROL(Emo, 21);
            Esu ^= Du;
            BCu = ROL(Esu, 14);
            Aba = BCa ^ ((~BCe) & BCi);
            Aba ^= (uint64_t)KeccakF_RoundConstants[round + 1];
            Abe = BCe ^ ((~BCi) & BCo);
            Abi = BCi ^ ((~BCo) & BCu);
            Abo = BCo ^ ((~BCu) & BCa);
            Abu = BCu ^ ((~BCa) & BCe);

            Ebo ^= Do;
            BCa = ROL(Ebo, 28);
            Egu ^= Du;
            BCe = ROL(Egu, 20);
            Eka ^= Da;
            BCi = ROL(Eka, 3);
            Eme ^= De;
            BCo = ROL(Eme, 45);
            Esi ^= Di;
            BCu = ROL(Esi, 61);
            Aga = BCa ^ ((~BCe) & BCi);
            Age = BCe ^ ((~BCi) & BCo);
            Agi = BCi ^ ((~BCo) & BCu);
            Ago = BCo ^ ((~BCu) & BCa);
            Agu = BCu ^ ((~BCa) & BCe);

            Ebe ^= De;
            BCa = ROL(Ebe, 1);
            Egi ^= Di;
            BCe = ROL(Egi, 6);
            Eko ^= Do;
            BCi = ROL(Eko, 25);
            Emu ^= Du;
            BCo = ROL(Emu, 8);
            Esa ^= Da;
            BCu = ROL(Esa, 18);
            Aka = BCa ^ ((~BCe) & BCi);
            Ake = BCe ^ ((~BCi) & BCo);
            Aki = BCi ^ ((~BCo) & BCu);
            Ako = BCo ^ ((~BCu) & BCa);
            Aku = BCu ^ ((~BCa) & BCe);

            Ebu ^= Du;
            BCa = ROL(Ebu, 27);
            Ega ^= Da;
            BCe = ROL(Ega, 36);
            Eke ^= De;
            BCi = ROL(Eke, 10);
            Emi ^= Di;
            BCo = ROL(Emi, 15);
            Eso ^= Do;
            BCu = ROL(Eso, 56);
            Ama = BCa ^ ((~BCe) & BCi);
            Ame = BCe ^ ((~BCi) & BCo);
            Ami = BCi ^ ((~BCo) & BCu);
            Amo = BCo ^ ((~BCu) & BCa);
            Amu = BCu ^ ((~BCa) & BCe);

            Ebi ^= Di;
            BCa = ROL(Ebi, 62);
            Ego ^= Do;
            BCe = ROL(Ego, 55);
            Eku ^= Du;
            BCi = ROL(Eku, 39);
            Ema ^= Da;
            BCo = ROL(Ema, 41);
            Ese ^= De;
            BCu = ROL(Ese, 2);
            Asa = BCa ^ ((~BCe) & BCi);
            Ase = BCe ^ ((~BCi) & BCo);
            Asi = BCi ^ ((~BCo) & BCu);
            Aso = BCo ^ ((~BCu) & BCa);
            Asu = BCu ^ ((~BCa) & BCe);
        }

        //copyToState(state, A)
        state[0] = Aba;
        state[1] = Abe;
        state[2] = Abi;
        state[3] = Abo;
        state[4] = Abu;
        state[5] = Aga;
        state[6] = Age;
        state[7] = Agi;
        state[8] = Ago;
        state[9] = Agu;
        state[10] = Aka;
        state[11] = Ake;
        state[12] = Aki;
        state[13] = Ako;
        state[14] = Aku;
        state[15] = Ama;
        state[16] = Ame;
        state[17] = Ami;
        state[18] = Amo;
        state[19] = Amu;
        state[20] = Asa;
        state[21] = Ase;
        state[22] = Asi;
        state[23] = Aso;
        state[24] = Asu;

#undef round
    }

    static void keccak_absorb(vector<uint64_t>& s,
        uint32_t r,
        vector<uint8_t>& m, uint64_t mlen,
        uint8_t p)
    {
        uint64_t i;
        vector<uint8_t> t(200);

        while (mlen >= r)
        {
            for (i = 0; i < r / 8; ++i) {
                vector<uint8_t> copy(m.begin() + 8 * i, m.end());
                s[i] ^= load64(copy);
                m.insert(m.begin() + 8 * i, copy.begin(), copy.end());
                m.resize(8 * i + copy.size());
            }

            KeccakF1600_StatePermute(s);
            mlen -= r;
            vector<uint8_t> copy(m.begin() + r, m.end());
            m = copy;
        }

        for (i = 0; i < r; ++i)
            t[i] = 0;
        for (i = 0; i < mlen; ++i)
            t[i] = m[i];
        t[i] = p;
        t[r - 1] |= 128;
        for (i = 0; i < r / 8; ++i) {
            vector<uint8_t> copy(t.begin() + 8 * i, t.end());
            s[i] ^= load64(copy);
            t.insert(t.begin() + 8 * i, copy.begin(), copy.end());
            t.resize(8 * i + copy.size());
        }
    }

    static void store64(vector<uint8_t>& x, uint64_t u)
    {
        uint32_t i;

        for (i = 0; i < 8; ++i)
        {
            x[i] = u;
            u >>= 8;
        }
    }

    static void keccak_squeezeblocks(vector<uint8_t>& h, uint64_t nblocks,
        vector<uint64_t>& s,
        uint32_t r)
    {
        uint32_t i;
        while (nblocks > 0)
        {
            KeccakF1600_StatePermute(s);
            for (i = 0; i < (r >> 3); i++)
            {
                vector<uint8_t> copy(h.begin() + 8 * i, h.end());
                store64(copy, s[i]);
                h.insert(h.begin() + 8 * i, copy.begin(), copy.end());
                h.resize(8 * i + copy.size());
            }
            vector<uint8_t> copy(h.begin() + r, h.end());
            h = copy;
            nblocks--;
        }
    }

    void shake128(vector<uint8_t>& output, uint64_t outlen,
        vector<uint8_t>& input, uint64_t inlen)
    {
        vector<uint64_t> s(25);
        vector<uint8_t> t(SHAKE128_RATE);
        uint64_t nblocks = outlen / SHAKE128_RATE;
        size_t i;

        for (i = 0; i < 25; ++i)
            s[i] = 0;

        /* Absorb input */
        keccak_absorb(s, SHAKE128_RATE, input, inlen, 0x1F);

        /* Squeeze output */
        keccak_squeezeblocks(output, nblocks, s, SHAKE128_RATE);

        vector<uint8_t> copy(output.begin() + nblocks * SHAKE128_RATE, output.end());
        output = copy;
        outlen -= nblocks * SHAKE128_RATE;

        if (outlen)
        {
            keccak_squeezeblocks(t, 1, s, SHAKE128_RATE);
            for (i = 0; i < outlen; i++)
                output[i] = t[i];
        }
    }

    static void BS2POLq(const vector<uint8_t>& bytes, vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = 13 * j;
            offset_data = 8 * j;
            data[offset_data + 0] = (bytes[offset_byte + 0] & (0xff)) | ((bytes[offset_byte + 1] & 0x1f) << 8);
            data[offset_data + 1] = (bytes[offset_byte + 1] >> 5 & (0x07)) | ((bytes[offset_byte + 2] & 0xff) << 3) | ((bytes[offset_byte + 3] & 0x03) << 11);
            data[offset_data + 2] = (bytes[offset_byte + 3] >> 2 & (0x3f)) | ((bytes[offset_byte + 4] & 0x7f) << 6);
            data[offset_data + 3] = (bytes[offset_byte + 4] >> 7 & (0x01)) | ((bytes[offset_byte + 5] & 0xff) << 1) | ((bytes[offset_byte + 6] & 0x0f) << 9);
            data[offset_data + 4] = (bytes[offset_byte + 6] >> 4 & (0x0f)) | ((bytes[offset_byte + 7] & 0xff) << 4) | ((bytes[offset_byte + 8] & 0x01) << 12);
            data[offset_data + 5] = (bytes[offset_byte + 8] >> 1 & (0x7f)) | ((bytes[offset_byte + 9] & 0x3f) << 7);
            data[offset_data + 6] = (bytes[offset_byte + 9] >> 6 & (0x03)) | ((bytes[offset_byte + 10] & 0xff) << 2) | ((bytes[offset_byte + 11] & 0x07) << 10);
            data[offset_data + 7] = (bytes[offset_byte + 11] >> 3 & (0x1f)) | ((bytes[offset_byte + 12] & 0xff) << 5);
        }
    }

    void BS2POLVECq(vector<uint8_t>& bytes, vector<vector<uint16_t>>& data)
    {
        size_t i;
        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(bytes.begin() + i * SABER_POLYBYTES, bytes.end());
            BS2POLq(copy, data[i]);
            bytes.insert(bytes.begin() + i * SABER_POLYBYTES, copy.begin(), copy.end());
            bytes.resize(i * SABER_POLYBYTES + copy.size());
        }
    }

    void GenMatrix(vector<vector<vector<uint16_t>>>& A, vector<uint8_t>& seed)
    {
        vector<uint8_t> buf(SABER_L * SABER_POLYVECBYTES);
        uint32_t i;

        shake128(buf, SABER_L * SABER_POLYVECBYTES, seed, SABER_SEEDBYTES);

        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(buf.begin() + i * SABER_POLYVECBYTES, buf.end());
            BS2POLVECq(copy, A[i]);
            buf.insert(buf.begin() + i * SABER_POLYVECBYTES, copy.begin(), copy.end());
            buf.resize(i * SABER_POLYVECBYTES + copy.size());
        }
    }

    static uint64_t load_littleendian(const vector<uint8_t>& x, uint32_t bytes)
    {
        uint32_t i;
        uint64_t r = x[0];
        for (i = 1; i < bytes; i++)
            r |= static_cast<uint64_t>(x[i]) << (8 * i);
        return r;
    }

    void cbd(vector<uint16_t>& s, vector<uint8_t>& buf)
    {
        uint64_t t, d;
        vector<uint64_t> a(4);
        vector<uint64_t> b(4);
        uint32_t i, j;

        for (i = 0; i < SABER_N / 4; i++)
        {
            vector<uint8_t> copy(buf.begin() + 5 * i, buf.end());
            t = load_littleendian(copy, 5);
            buf.insert(buf.begin() + 5 * i, copy.begin(), copy.end());
            buf.resize(5 * i + copy.size());
            d = 0;
            for (j = 0; j < 5; j++)
                d += (t >> j) & 0x0842108421UL;

            a[0] = d & 0x1f;
            b[0] = (d >> 5) & 0x1f;
            a[1] = (d >> 10) & 0x1f;
            b[1] = (d >> 15) & 0x1f;
            a[2] = (d >> 20) & 0x1f;
            b[2] = (d >> 25) & 0x1f;
            a[3] = (d >> 30) & 0x1f;
            b[3] = (d >> 35);

            s[4 * i + 0] = static_cast<uint16_t>(a[0] - b[0]);
            s[4 * i + 1] = static_cast<uint16_t>(a[1] - b[1]);
            s[4 * i + 2] = static_cast<uint16_t>(a[2] - b[2]);
            s[4 * i + 3] = static_cast<uint16_t>(a[3] - b[3]);
        }
    }

    void GenSecret(vector<vector<uint16_t>>& s, vector<uint8_t>& seed)
    {
        vector<uint8_t> buf(SABER_L * SABER_POLYCOINBYTES);
        size_t i;

        shake128(buf, sizeof(buf), seed, SABER_NOISE_SEEDBYTES);

        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(buf.begin() + i * SABER_POLYCOINBYTES, buf.end());
            cbd(s[i], copy);
            buf.insert(buf.begin() + i * SABER_POLYCOINBYTES, copy.begin(), copy.end());
            buf.resize(i * SABER_POLYCOINBYTES + copy.size());
        }
    }

    static void karatsuba_simple(const vector<uint16_t>& a_1, const vector<uint16_t>& b_1, vector<uint16_t>& result_final) {
        vector<uint16_t> d01(KARATSUBA_N / 2 - 1);
        vector<uint16_t> d0123(KARATSUBA_N / 2 - 1);
        vector<uint16_t> d23(KARATSUBA_N / 2 - 1);
        vector<uint16_t> result_d01(KARATSUBA_N - 1);

        for (uint32_t i = 0; i < KARATSUBA_N - 1; i++) {
            result_d01[i] = 0;
        }
        for (uint32_t i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            d01[i] = 0;
            d0123[i] = 0;
            d23[i] = 0;
        }
        for (uint32_t i = 0; i < 2 * KARATSUBA_N - 1; i++) {
            result_final[i] = 0;
        }

        int32_t i, j;

        uint16_t acc1, acc2, acc3, acc4, acc5, acc6, acc7, acc8, acc9, acc10;


        for (i = 0; i < KARATSUBA_N / 4; i++) {
            acc1 = a_1[i]; //a0
            acc2 = a_1[i + KARATSUBA_N / 4]; //a1
            acc3 = a_1[i + 2 * KARATSUBA_N / 4]; //a2
            acc4 = a_1[i + 3 * KARATSUBA_N / 4]; //a3
            for (j = 0; j < KARATSUBA_N / 4; j++) {

                acc5 = b_1[j]; //b0
                acc6 = b_1[j + KARATSUBA_N / 4]; //b1

                result_final[i + j + 0 * KARATSUBA_N / 4] =
                    result_final[i + j + 0 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc1, acc5);
                result_final[i + j + 2 * KARATSUBA_N / 4] =
                    result_final[i + j + 2 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc2, acc6);

                acc7 = acc5 + acc6; //b01
                acc8 = acc1 + acc2; //a01
                d01[i + j] = d01[i + j] + static_cast<uint16_t>(acc7 * static_cast<uint64_t>(acc8));
                //--------------------------------------------------------

                acc7 = b_1[j + 2 * KARATSUBA_N / 4]; //b2
                acc8 = b_1[j + 3 * KARATSUBA_N / 4]; //b3
                result_final[i + j + 4 * KARATSUBA_N / 4] =
                    result_final[i + j + 4 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc7, acc3);

                result_final[i + j + 6 * KARATSUBA_N / 4] =
                    result_final[i + j + 6 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc8, acc4);

                acc9 = acc3 + acc4;
                acc10 = acc7 + acc8;
                d23[i + j] = d23[i + j] + OVERFLOWING_MUL(acc9, acc10);
                //--------------------------------------------------------

                acc5 = acc5 + acc7; //b02
                acc7 = acc1 + acc3; //a02
                result_d01[i + j + 0 * KARATSUBA_N / 4] =
                    result_d01[i + j + 0 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc5, acc7);

                acc6 = acc6 + acc8; //b13
                acc8 = acc2 + acc4;
                result_d01[i + j + 2 * KARATSUBA_N / 4] =
                    result_d01[i + j + 2 * KARATSUBA_N / 4] +
                    OVERFLOWING_MUL(acc6, acc8);

                acc5 = acc5 + acc6;
                acc7 = acc7 + acc8;
                d0123[i + j] = d0123[i + j] + OVERFLOWING_MUL(acc5, acc7);
            }
        }

        // 2nd last stage

        for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            d0123[i] = d0123[i] - result_d01[i + 0 * KARATSUBA_N / 4] - result_d01[i + 2 * KARATSUBA_N / 4];
            d01[i] = d01[i] - result_final[i + 0 * KARATSUBA_N / 4] - result_final[i + 2 * KARATSUBA_N / 4];
            d23[i] = d23[i] - result_final[i + 4 * KARATSUBA_N / 4] - result_final[i + 6 * KARATSUBA_N / 4];
        }

        for (i = 0; i < KARATSUBA_N / 2 - 1; i++) {
            result_d01[i + 1 * KARATSUBA_N / 4] = result_d01[i + 1 * KARATSUBA_N / 4] + d0123[i];
            result_final[i + 1 * KARATSUBA_N / 4] = result_final[i + 1 * KARATSUBA_N / 4] + d01[i];
            result_final[i + 5 * KARATSUBA_N / 4] = result_final[i + 5 * KARATSUBA_N / 4] + d23[i];
        }

        // Last stage
        for (i = 0; i < KARATSUBA_N - 1; i++) {
            result_d01[i] = result_d01[i] - result_final[i] - result_final[i + KARATSUBA_N];
        }

        for (i = 0; i < KARATSUBA_N - 1; i++) {
            result_final[i + 1 * KARATSUBA_N / 2] = result_final[i + 1 * KARATSUBA_N / 2] + result_d01[i];
        }

    }

    static void toom_cook_4way(const vector<uint16_t>& a1, const vector<uint16_t>& b1, vector<uint16_t>& result) {
        uint16_t inv3 = 43691, inv9 = 36409, inv15 = 61167;

        vector<uint16_t> aw1(N_SB);
        vector<uint16_t> aw2(N_SB);
        vector<uint16_t> aw3(N_SB);
        vector<uint16_t> aw4(N_SB);
        vector<uint16_t> aw5(N_SB);
        vector<uint16_t> aw6(N_SB);
        vector<uint16_t> aw7(N_SB);
        vector<uint16_t> bw1(N_SB);
        vector<uint16_t> bw2(N_SB);
        vector<uint16_t> bw3(N_SB);
        vector<uint16_t> bw4(N_SB);
        vector<uint16_t> bw5(N_SB);
        vector<uint16_t> bw6(N_SB);
        vector<uint16_t> bw7(N_SB);
        vector<uint16_t> w1(N_SB_RES);
        vector<uint16_t> w2(N_SB_RES);
        vector<uint16_t> w3(N_SB_RES);
        vector<uint16_t> w4(N_SB_RES);
        vector<uint16_t> w5(N_SB_RES);
        vector<uint16_t> w6(N_SB_RES);
        vector<uint16_t> w7(N_SB_RES);
        for (uint32_t i = 0; i < N_SB_RES; i++) {
            w1[i] = 0;
            w2[i] = 0;
            w3[i] = 0;
            w4[i] = 0;
            w5[i] = 0;
            w6[i] = 0;
            w7[i] = 0;
        }
        uint16_t r0, r1, r2, r3, r4, r5, r6, r7;
        vector<uint16_t> A0(a1.begin(), a1.end());
        vector<uint16_t> A1(a1.begin() + N_SB, a1.end());
        vector<uint16_t> A2(a1.begin() + 2 * N_SB, a1.end());
        vector<uint16_t> A3(a1.begin() + 3 * N_SB, a1.end());
        vector<uint16_t> B0(b1.begin(), b1.end());
        vector<uint16_t> B1(b1.begin() + N_SB, b1.end());
        vector<uint16_t> B2(b1.begin() + 2 * N_SB, b1.end());
        vector<uint16_t> B3(b1.begin() + 3 * N_SB, b1.end());

        vector<uint16_t> C;
        C = result;

        uint32_t i, j;

        // EVALUATION
        for (j = 0; j < N_SB; ++j) {
            r0 = A0[j];
            r1 = A1[j];
            r2 = A2[j];
            r3 = A3[j];
            r4 = r0 + r2;
            r5 = r1 + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            aw3[j] = r6;
            aw4[j] = r7;
            r4 = ((r0 << 2) + r2) << 1;
            r5 = (r1 << 2) + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            aw5[j] = r6;
            aw6[j] = r7;
            r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
            aw2[j] = r4;
            aw7[j] = r0;
            aw1[j] = r3;
        }
        for (j = 0; j < N_SB; ++j) {
            r0 = B0[j];
            r1 = B1[j];
            r2 = B2[j];
            r3 = B3[j];
            r4 = r0 + r2;
            r5 = r1 + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            bw3[j] = r6;
            bw4[j] = r7;
            r4 = ((r0 << 2) + r2) << 1;
            r5 = (r1 << 2) + r3;
            r6 = r4 + r5;
            r7 = r4 - r5;
            bw5[j] = r6;
            bw6[j] = r7;
            r4 = (r3 << 3) + (r2 << 2) + (r1 << 1) + r0;
            bw2[j] = r4;
            bw7[j] = r0;
            bw1[j] = r3;
        }

        // MULTIPLICATION

        karatsuba_simple(aw1, bw1, w1);
        karatsuba_simple(aw2, bw2, w2);
        karatsuba_simple(aw3, bw3, w3);
        karatsuba_simple(aw4, bw4, w4);
        karatsuba_simple(aw5, bw5, w5);
        karatsuba_simple(aw6, bw6, w6);
        karatsuba_simple(aw7, bw7, w7);

        // INTERPOLATION
        for (i = 0; i < N_SB_RES; ++i) {
            r0 = w1[i];
            r1 = w2[i];
            r2 = w3[i];
            r3 = w4[i];
            r4 = w5[i];
            r5 = w6[i];
            r6 = w7[i];

            r1 = r1 + r4;
            r5 = r5 - r4;
            r3 = ((r3 - r2) >> 1);
            r4 = r4 - r0;
            r4 = r4 - (r6 << 6);
            r4 = (r4 << 1) + r5;
            r2 = r2 + r3;
            r1 = r1 - (r2 << 6) - r2;
            r2 = r2 - r6;
            r2 = r2 - r0;
            r1 = r1 + 45 * r2;
            r4 = static_cast<uint16_t>(((r4 - (r2 << 3)) * static_cast<uint32_t>(inv3)) >> 3);
            r5 = r5 + r1;
            r1 = static_cast<uint16_t>(((r1 + (r3 << 4)) * static_cast<uint32_t>(inv9)) >> 1);
            r3 = -(r3 + r1);
            r5 = static_cast<uint16_t>(((30 * r1 - r5) * static_cast<uint32_t>(inv15)) >> 2);
            r2 = r2 - r4;
            r1 = r1 - r5;

            C[i] += r6;
            C[i + 64] += r5;
            C[i + 128] += r4;
            C[i + 192] += r3;
            C[i + 256] += r2;
            C[i + 320] += r1;
            C[i + 384] += r0;
        }
    }

    /* res += a*b */
    void poly_mul_acc(const vector<uint16_t>& a, const vector<uint16_t>& b, vector<uint16_t>& res)
    {
        vector<uint16_t> c(2 * SABER_N);
        for (uint32_t i = 0; i < 2 * SABER_N; i++) {
            c[i] = 0;
        }
        uint32_t i;

        toom_cook_4way(a, b, c);

        /* reduction */
        for (i = SABER_N; i < 2 * SABER_N; i++)
        {
            res[i - SABER_N] += (c[i - SABER_N] - c[i]);
        }
    }

    void MatrixVectorMul(const vector<vector<vector<uint16_t>>>& A, const vector<vector<uint16_t>>& s, vector<vector<uint16_t>>& res, int16_t transpose)
    {
        uint32_t i, j;
        for (i = 0; i < SABER_L; i++)
        {
            for (j = 0; j < SABER_L; j++)
            {
                if (transpose == 1)
                {
                    poly_mul_acc(A[j][i], s[j], res[i]);
                }
                else
                {
                    poly_mul_acc(A[i][j], s[j], res[i]);
                }
            }
        }
    }

    static void POLq2BS(vector<uint8_t>& bytes, const vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = 13 * j;
            offset_data = 8 * j;
            bytes[offset_byte + 0] = (data[offset_data + 0] & (0xff));
            bytes[offset_byte + 1] = ((data[offset_data + 0] >> 8) & 0x1f) | ((data[offset_data + 1] & 0x07) << 5);
            bytes[offset_byte + 2] = ((data[offset_data + 1] >> 3) & 0xff);
            bytes[offset_byte + 3] = ((data[offset_data + 1] >> 11) & 0x03) | ((data[offset_data + 2] & 0x3f) << 2);
            bytes[offset_byte + 4] = ((data[offset_data + 2] >> 6) & 0x7f) | ((data[offset_data + 3] & 0x01) << 7);
            bytes[offset_byte + 5] = ((data[offset_data + 3] >> 1) & 0xff);
            bytes[offset_byte + 6] = ((data[offset_data + 3] >> 9) & 0x0f) | ((data[offset_data + 4] & 0x0f) << 4);
            bytes[offset_byte + 7] = ((data[offset_data + 4] >> 4) & 0xff);
            bytes[offset_byte + 8] = ((data[offset_data + 4] >> 12) & 0x01) | ((data[offset_data + 5] & 0x7f) << 1);
            bytes[offset_byte + 9] = ((data[offset_data + 5] >> 7) & 0x3f) | ((data[offset_data + 6] & 0x03) << 6);
            bytes[offset_byte + 10] = ((data[offset_data + 6] >> 2) & 0xff);
            bytes[offset_byte + 11] = ((data[offset_data + 6] >> 10) & 0x07) | ((data[offset_data + 7] & 0x1f) << 3);
            bytes[offset_byte + 12] = ((data[offset_data + 7] >> 5) & 0xff);
        }
    }

    void POLVECq2BS(vector<uint8_t>& bytes, const vector<vector<uint16_t>>& data)
    {
        size_t i;
        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(bytes.begin() + i * SABER_POLYBYTES, bytes.end());
            POLq2BS(copy, data[i]);
            bytes.insert(bytes.begin() + i * SABER_POLYBYTES, copy.begin(), copy.end());
            bytes.resize(i * SABER_POLYBYTES + copy.size());
        }
    }

    static void POLp2BS(vector<uint8_t>& bytes, const vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 4; j++)
        {
            offset_byte = 5 * j;
            offset_data = 4 * j;
            bytes[offset_byte + 0] = (data[offset_data + 0] & (0xff));
            bytes[offset_byte + 1] = ((data[offset_data + 0] >> 8) & 0x03) | ((data[offset_data + 1] & 0x3f) << 2);
            bytes[offset_byte + 2] = ((data[offset_data + 1] >> 6) & 0x0f) | ((data[offset_data + 2] & 0x0f) << 4);
            bytes[offset_byte + 3] = ((data[offset_data + 2] >> 4) & 0x3f) | ((data[offset_data + 3] & 0x03) << 6);
            bytes[offset_byte + 4] = ((data[offset_data + 3] >> 2) & 0xff);
        }
    }

    void POLVECp2BS(vector<uint8_t>& bytes, const vector<vector<uint16_t>>& data)
    {
        size_t i;
        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(bytes.begin() + i * (SABER_EP * SABER_N / 8), bytes.end());
            POLp2BS(copy, data[i]);
            bytes.insert(bytes.begin() + i * (SABER_EP * SABER_N / 8), copy.begin(), copy.end());
            bytes.resize(i * (SABER_EP * SABER_N / 8) + copy.size());
        }
    }

    void sha3_256(vector<uint8_t>& output, vector<uint8_t>& input, uint64_t inlen)
    {
        vector<uint64_t> s(25);
        vector<uint8_t> t(SHA3_256_RATE);
        size_t i;

        for (i = 0; i < 25; ++i)
            s[i] = 0;

        /* Absorb input */
        keccak_absorb(s, SHA3_256_RATE, input, inlen, 0x06);

        /* Squeeze output */
        keccak_squeezeblocks(t, 1, s, SHA3_256_RATE);

        for (i = 0; i < 32; i++)
            output[i] = t[i];
    }

    static void BS2POLp(const vector<uint8_t>& bytes, vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 4; j++)
        {
            offset_byte = 5 * j;
            offset_data = 4 * j;
            data[offset_data + 0] = (bytes[offset_byte + 0] & (0xff)) | ((bytes[offset_byte + 1] & 0x03) << 8);
            data[offset_data + 1] = ((bytes[offset_byte + 1] >> 2) & (0x3f)) | ((bytes[offset_byte + 2] & 0x0f) << 6);
            data[offset_data + 2] = ((bytes[offset_byte + 2] >> 4) & (0x0f)) | ((bytes[offset_byte + 3] & 0x3f) << 4);
            data[offset_data + 3] = ((bytes[offset_byte + 3] >> 6) & (0x03)) | ((bytes[offset_byte + 4] & 0xff) << 2);
        }
    }

    void BS2POLVECp(vector<uint8_t>& bytes, vector<vector<uint16_t>>& data)
    {
        size_t i;
        for (i = 0; i < SABER_L; i++)
        {
            vector<uint8_t> copy(bytes.begin() + i * (SABER_EP * SABER_N / 8), bytes.end());
            BS2POLp(copy, data[i]);
            bytes.insert(bytes.begin() + i * (SABER_EP * SABER_N / 8), copy.begin(), copy.end());
            bytes.resize(i * (SABER_EP * SABER_N / 8) + copy.size());
        }
    }

    void InnerProd(const vector<vector<uint16_t>>& b, const vector<vector<uint16_t>>& s, vector<uint16_t>& res)
    {
        uint32_t j;
        for (j = 0; j < SABER_L; j++)
        {
            poly_mul_acc(b[j], s[j], res);
        }
    }

    void BS2POLmsg(const vector<uint8_t>& bytes, vector<uint16_t>& data)
    {
        size_t i, j;
        for (j = 0; j < SABER_KEYBYTES; j++)
        {
            for (i = 0; i < 8; i++)
            {
                data[j * 8 + i] = ((bytes[j] >> i) & 0x01);
            }
        }
    }

    void POLT2BS(vector<uint8_t>& bytes, const vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = 3 * j;
            offset_data = 8 * j;
            bytes[offset_byte + 0] = (data[offset_data + 0] & 0x7) | ((data[offset_data + 1] & 0x7) << 3) | ((data[offset_data + 2] & 0x3) << 6);
            bytes[offset_byte + 1] = ((data[offset_data + 2] >> 2) & 0x01) | ((data[offset_data + 3] & 0x7) << 1) | ((data[offset_data + 4] & 0x7) << 4) | (((data[offset_data + 5]) & 0x01) << 7);
            bytes[offset_byte + 2] = ((data[offset_data + 5] >> 1) & 0x03) | ((data[offset_data + 6] & 0x7) << 2) | ((data[offset_data + 7] & 0x7) << 5);
        }
    }

    void sha3_512(vector<uint8_t>& output, vector<uint8_t>& input, uint64_t inlen)
    {
        vector<uint64_t> s(25);
        vector<uint8_t> t(SHA3_512_RATE);
        size_t i;

        for (i = 0; i < 25; ++i)
            s[i] = 0;

        /* Absorb input */
        keccak_absorb(s, SHA3_512_RATE, input, inlen, 0x06);

        /* Squeeze output */
        keccak_squeezeblocks(t, 1, s, SHA3_512_RATE);

        for (i = 0; i < 64; i++)
            output[i] = t[i];
    }

    void BS2POLT(const vector<uint8_t>& bytes, vector<uint16_t>& data)
    {
        size_t j, offset_byte, offset_data;
        for (j = 0; j < SABER_N / 8; j++)
        {
            offset_byte = 3 * j;
            offset_data = 8 * j;
            data[offset_data + 0] = (bytes[offset_byte + 0]) & 0x07;
            data[offset_data + 1] = ((bytes[offset_byte + 0]) >> 3) & 0x07;
            data[offset_data + 2] = (((bytes[offset_byte + 0]) >> 6) & 0x03) | (((bytes[offset_byte + 1]) & 0x01) << 2);
            data[offset_data + 3] = ((bytes[offset_byte + 1]) >> 1) & 0x07;
            data[offset_data + 4] = ((bytes[offset_byte + 1]) >> 4) & 0x07;
            data[offset_data + 5] = (((bytes[offset_byte + 1]) >> 7) & 0x01) | (((bytes[offset_byte + 2]) & 0x03) << 1);
            data[offset_data + 6] = ((bytes[offset_byte + 2] >> 2) & 0x07);
            data[offset_data + 7] = ((bytes[offset_byte + 2] >> 5) & 0x07);
        }
    }

    void POLmsg2BS(vector<uint8_t>& bytes, const vector<uint16_t>& data)
    {
        for (uint32_t i = 0; i < SABER_KEYBYTES; i++) {
            bytes[i] = 0;
        }
        size_t i, j;

        for (j = 0; j < SABER_KEYBYTES; j++)
        {
            for (i = 0; i < 8; i++)
            {
                bytes[j] = bytes[j] | ((data[j * 8 + i] & 0x01) << i);
            }
        }
    }

    /* returns 0 for equal strings, 1 for non-equal strings */
    uint32_t verify(const vector<uint8_t>& a, const vector<uint8_t>& b, size_t len)
    {
        int64_t r;
        size_t i;
        r = 0;

        for (i = 0; i < len; i++)
            r |= a[i] ^ b[i];

        r = (-r) >> 63;
        return r;
    }

    /* b = 1 means mov, b = 0 means don't mov*/
    void cmov(vector<uint8_t>& r, const vector<uint8_t>& x, size_t len, uint8_t b)
    {
        size_t i;

        b = -b;
        for (i = 0; i < len; i++)
            r[i] ^= b & (x[i] ^ r[i]);
    }

}
