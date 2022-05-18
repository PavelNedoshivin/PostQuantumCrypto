#include "CrystalsKyberUtils.hpp"

using namespace std;

namespace CrystalsKyber {

    void randombytes(vector<uint8_t>& out, size_t outlen) {
        HCRYPTPROV ctx;
        size_t len;

        if (!CryptAcquireContext(&ctx, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
            abort();

        while (outlen > 0) {
            len = (outlen > 1048576) ? 1048576 : outlen;
            if (!CryptGenRandom(ctx, len, (BYTE*)&out[0]))
                abort();

            vector<uint8_t> copy(out.begin() + len, out.end());
            out = copy;
            outlen -= len;
        }

        if (!CryptReleaseContext(ctx, 0))
            abort();
    }

    /*************************************************
    * Name:        load64
    *
    * Description: Load 8 bytes into uint64_t in little-endian order
    *
    * Arguments:   - const uint8_t *x: pointer to input byte array
    *
    * Returns the loaded 64-bit unsigned integer
    **************************************************/
    static uint64_t load64(const vector<uint8_t>& x) {
        uint32_t i;
        uint64_t r = 0;

        for (i = 0; i < 8; i++)
            r |= (uint64_t)x[i] << 8 * i;

        return r;
    }

    /* Keccak round constants */
    static const uint64_t KeccakF_RoundConstants[NROUNDS] = {
      (uint64_t)0x0000000000000001ULL,
      (uint64_t)0x0000000000008082ULL,
      (uint64_t)0x800000000000808aULL,
      (uint64_t)0x8000000080008000ULL,
      (uint64_t)0x000000000000808bULL,
      (uint64_t)0x0000000080000001ULL,
      (uint64_t)0x8000000080008081ULL,
      (uint64_t)0x8000000000008009ULL,
      (uint64_t)0x000000000000008aULL,
      (uint64_t)0x0000000000000088ULL,
      (uint64_t)0x0000000080008009ULL,
      (uint64_t)0x000000008000000aULL,
      (uint64_t)0x000000008000808bULL,
      (uint64_t)0x800000000000008bULL,
      (uint64_t)0x8000000000008089ULL,
      (uint64_t)0x8000000000008003ULL,
      (uint64_t)0x8000000000008002ULL,
      (uint64_t)0x8000000000000080ULL,
      (uint64_t)0x000000000000800aULL,
      (uint64_t)0x800000008000000aULL,
      (uint64_t)0x8000000080008081ULL,
      (uint64_t)0x8000000000008080ULL,
      (uint64_t)0x0000000080000001ULL,
      (uint64_t)0x8000000080008008ULL
    };

    /*************************************************
    * Name:        KeccakF1600_StatePermute
    *
    * Description: The Keccak F1600 Permutation
    *
    * Arguments:   - uint64_t *state: pointer to input/output Keccak state
    **************************************************/
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

        for (round = 0; round < NROUNDS; round += 2) {
            //    prepareTheta
            BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
            BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
            BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
            BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
            BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;

            //thetaRhoPiChiIotaPrepareTheta(round, A, E)
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
            Eba ^= (uint64_t)KeccakF_RoundConstants[round];
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
    }

    /*************************************************
    * Name:        keccak_absorb_once
    *
    * Description: Absorb step of Keccak;
    *              non-incremental, starts by zeroeing the state.
    *
    * Arguments:   - uint64_t *s: pointer to (uninitialized) output Keccak state
    *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
    *              - const uint8_t *in: pointer to input to be absorbed into s
    *              - size_t inlen: length of input in bytes
    *              - uint8_t p: domain-separation byte for different Keccak-derived functions
    **************************************************/
    static void keccak_absorb_once(vector<uint64_t>& s,
        uint32_t r,
        vector<uint8_t>& in,
        size_t inlen,
        uint8_t p)
    {
        uint32_t i;

        for (i = 0; i < 25; i++)
            s[i] = 0;

        uint32_t in_ptr = 0;
        while (inlen >= r) {
            for (i = 0; i < r / 8; i++) {
                vector<uint8_t> copy(in.begin() + 8 * i, in.end());
                s[i] ^= load64(copy);
                in.insert(in.begin() + 8 * i, copy.begin(), copy.end());
                in.resize(8 * i + copy.size());
            }
            in_ptr += r;
            inlen -= r;
            KeccakF1600_StatePermute(s);
        }

        for (i = 0; i < inlen; i++)
            s[i / 8] ^= (uint64_t)in[i] << 8 * (i % 8);

        s[i / 8] ^= (uint64_t)p << 8 * (i % 8);
        s[(r - 1) / 8] ^= 1ULL << 63;
    }

    /*************************************************
    * Name:        store64
    *
    * Description: Store a 64-bit integer to array of 8 bytes in little-endian order
    *
    * Arguments:   - uint8_t *x: pointer to the output byte array (allocated)
    *              - uint64_t u: input 64-bit unsigned integer
    **************************************************/
    static void store64(vector<uint8_t>& x, uint64_t u) {
        uint32_t i;

        for (i = 0; i < 8; i++)
            x[i] = u >> 8 * i;
    }

    /*************************************************
    * Name:        sha3_512
    *
    * Description: SHA3-512 with non-incremental API
    *
    * Arguments:   - uint8_t *h: pointer to output (64 bytes)
    *              - const uint8_t *in: pointer to input
    *              - size_t inlen: length of input in bytes
    **************************************************/
    void sha3_512(vector<uint8_t>& h, vector<uint8_t>& in, size_t inlen)
    {
        uint32_t i;
        vector<uint64_t> s(25);

        keccak_absorb_once(s, SHA3_512_RATE, in, inlen, 0x06);
        KeccakF1600_StatePermute(s);
        for (i = 0; i < 8; i++) {
            vector<uint8_t> copy(h.begin() + 8 * i, h.end());
            store64(copy, s[i]);
            h.insert(h.begin() + 8 * i, copy.begin(), copy.end());
            h.resize(8 * i + copy.size());
        }
    }

    /*************************************************
    * Name:        shake128_absorb_once
    *
    * Description: Initialize, absorb into and finalize SHAKE128 XOF; non-incremental.
    *
    * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
    *              - const uint8_t *in: pointer to input to be absorbed into s
    *              - size_t inlen: length of input in bytes
    **************************************************/
    void shake128_absorb_once(keccak_state& state, vector<uint8_t>& in, size_t inlen)
    {
        keccak_absorb_once(state.s, SHAKE128_RATE, in, inlen, 0x1F);
        state.pos = SHAKE128_RATE;
    }

    /*************************************************
    * Name:        kyber_shake128_absorb
    *
    * Description: Absorb step of the SHAKE128 specialized for the Kyber context.
    *
    * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
    *              - const uint8_t *seed: pointer to KYBER_SYMBYTES input to be absorbed into state
    *              - uint8_t i: additional byte of input
    *              - uint8_t j: additional byte of input
    **************************************************/
    void kyber_shake128_absorb(keccak_state& state,
        const vector<uint8_t>& seed,
        uint8_t x,
        uint8_t y)
    {
        vector<uint8_t> extseed(KYBER_SYMBYTES + 2);

        extseed.insert(extseed.begin(), seed.begin(), seed.begin() + KYBER_SYMBYTES);
        extseed.resize(KYBER_SYMBYTES + 2);
        extseed[KYBER_SYMBYTES + 0] = x;
        extseed[KYBER_SYMBYTES + 1] = y;

        shake128_absorb_once(state, extseed, sizeof(uint8_t) * (KYBER_SYMBYTES + 2));
    }

    /*************************************************
    * Name:        keccak_squeezeblocks
    *
    * Description: Squeeze step of Keccak. Squeezes full blocks of r bytes each.
    *              Modifies the state. Can be called multiple times to keep
    *              squeezing, i.e., is incremental. Assumes zero bytes of current
    *              block have already been squeezed.
    *
    * Arguments:   - uint8_t *out: pointer to output blocks
    *              - size_t nblocks: number of blocks to be squeezed (written to out)
    *              - uint64_t *s: pointer to input/output Keccak state
    *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
    **************************************************/
    static void keccak_squeezeblocks(vector<uint8_t>& out,
        size_t nblocks,
        vector<uint64_t>& s,
        uint32_t r)
    {
        uint32_t i;

        uint32_t out_ptr = 0;
        while (nblocks) {
            KeccakF1600_StatePermute(s);
            for (i = 0; i < min(r / 8, (out.size() - out_ptr) / 8); i++) {
                vector<uint8_t> copy(out.begin() + out_ptr + 8 * i, out.end());
                store64(copy, s[i]);
                out.insert(out.begin() + out_ptr + 8 * i, copy.begin(), copy.end());
                out.resize(out_ptr + 8 * i + copy.size());
            }
            out_ptr += r;
            nblocks -= 1;
        }
    }

    /*************************************************
    * Name:        shake128_squeezeblocks
    *
    * Description: Squeeze step of SHAKE128 XOF. Squeezes full blocks of
    *              SHAKE128_RATE bytes each. Can be called multiple times
    *              to keep squeezing. Assumes new block has not yet been
    *              started (state->pos = SHAKE128_RATE).
    *
    * Arguments:   - uint8_t *out: pointer to output blocks
    *              - size_t nblocks: number of blocks to be squeezed (written to output)
    *              - keccak_state *s: pointer to input/output Keccak state
    **************************************************/
    void shake128_squeezeblocks(vector<uint8_t>& out, size_t nblocks, keccak_state& state)
    {
        keccak_squeezeblocks(out, nblocks, state.s, SHAKE128_RATE);
    }

    /*************************************************
    * Name:        rej_uniform
    *
    * Description: Run rejection sampling on uniform random bytes to generate
    *              uniform random integers mod q
    *
    * Arguments:   - int16_t *r: pointer to output buffer
    *              - unsigned int len: requested number of 16-bit integers (uniform mod q)
    *              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
    *              - unsigned int buflen: length of input buffer in bytes
    *
    * Returns number of sampled 16-bit integers (at most len)
    **************************************************/
    static uint32_t rej_uniform(vector<int16_t>& r,
        uint32_t len,
        const vector<uint8_t>& buf,
        uint32_t buflen)
    {
        uint32_t ctr, pos;
        uint16_t val0, val1;

        ctr = pos = 0;
        while (ctr < len && pos + 3 <= buflen) {
            val0 = ((buf[pos + 0] >> 0) | ((uint16_t)buf[pos + 1] << 8)) & 0xFFF;
            val1 = ((buf[pos + 1] >> 4) | ((uint16_t)buf[pos + 2] << 4)) & 0xFFF;
            pos += 3;

            if (val0 < KYBER_Q)
                r[ctr++] = val0;
            if (ctr < len && val1 < KYBER_Q)
                r[ctr++] = val1;
        }

        return ctr;
    }

    /*************************************************
    * Name:        gen_matrix
    *
    * Description: Deterministically generate matrix A (or the transpose of A)
    *              from a seed. Entries of the matrix are polynomials that look
    *              uniformly random. Performs rejection sampling on output of
    *              a XOF
    *
    * Arguments:   - polyvec *a: pointer to ouptput matrix A
    *              - const uint8_t *seed: pointer to input seed
    *              - int transposed: boolean deciding whether A or A^T is generated
    **************************************************/
    // Not static for benchmarking
    void gen_matrix(vector<polyvec>& a, const vector<uint8_t>& seed, uint32_t transposed)
    {
        uint32_t ctr, i, j, k;
        uint32_t buflen, off;
        vector<uint8_t> buf(GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES + 2);
        xof_state state;
        state.s.resize(25);

        for (i = 0; i < KYBER_K; i++) {
            for (j = 0; j < KYBER_K; j++) {
                if (transposed)
                    xof_absorb(state, seed, i, j);
                else
                    xof_absorb(state, seed, j, i);

                xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, state);
                buflen = GEN_MATRIX_NBLOCKS * XOF_BLOCKBYTES;
                ctr = rej_uniform(a[i].vec[j].coeffs, KYBER_N, buf, buflen);

                while (ctr < KYBER_N) {
                    off = buflen % 3;
                    for (k = 0; k < off; k++)
                        buf[k] = buf[buflen - off + k];
                    vector<uint8_t> copy(buf.begin() + off, buf.end());
                    xof_squeezeblocks(copy, 1, state);
                    buf.insert(buf.begin() + off, copy.begin(), copy.end());
                    buf.resize(off + copy.size());
                    buflen = off + XOF_BLOCKBYTES;
                    vector<int16_t> copyC(a[i].vec[j].coeffs.begin() + ctr, a[i].vec[j].coeffs.end());
                    ctr += rej_uniform(copyC, KYBER_N - ctr, buf, buflen);
                    a[i].vec[j].coeffs.insert(a[i].vec[j].coeffs.begin() + ctr, copyC.begin(), copyC.end());
                    a[i].vec[j].coeffs.resize(ctr + copyC.size());
                }
            }
        }
    }

    /*************************************************
    * Name:        shake256_absorb_once
    *
    * Description: Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
    *
    * Arguments:   - keccak_state *state: pointer to (uninitialized) output Keccak state
    *              - const uint8_t *in: pointer to input to be absorbed into s
    *              - size_t inlen: length of input in bytes
    **************************************************/
    void shake256_absorb_once(keccak_state& state, vector<uint8_t>& in, size_t inlen)
    {
        keccak_absorb_once(state.s, SHAKE256_RATE, in, inlen, 0x1F);
        state.pos = SHAKE256_RATE;
    }

    /*************************************************
    * Name:        shake256_squeezeblocks
    *
    * Description: Squeeze step of SHAKE256 XOF. Squeezes full blocks of
    *              SHAKE256_RATE bytes each. Can be called multiple times
    *              to keep squeezing. Assumes next block has not yet been
    *              started (state->pos = SHAKE256_RATE).
    *
    * Arguments:   - uint8_t *out: pointer to output blocks
    *              - size_t nblocks: number of blocks to be squeezed (written to output)
    *              - keccak_state *s: pointer to input/output Keccak state
    **************************************************/
    void shake256_squeezeblocks(vector<uint8_t>& out, size_t nblocks, keccak_state& state)
    {
        keccak_squeezeblocks(out, nblocks, state.s, SHAKE256_RATE);
    }

    /*************************************************
    * Name:        keccak_squeeze
    *
    * Description: Squeeze step of Keccak. Squeezes arbitratrily many bytes.
    *              Modifies the state. Can be called multiple times to keep
    *              squeezing, i.e., is incremental.
    *
    * Arguments:   - uint8_t *out: pointer to output
    *              - size_t outlen: number of bytes to be squeezed (written to out)
    *              - uint64_t *s: pointer to input/output Keccak state
    *              - unsigned int pos: number of bytes in current block already squeezed
    *              - unsigned int r: rate in bytes (e.g., 168 for SHAKE128)
    *
    * Returns new position pos in current block
    **************************************************/
    static uint32_t keccak_squeeze(vector<uint8_t>& out,
        size_t outlen,
        vector<uint64_t> s,
        uint32_t pos,
        uint32_t r)
    {
        uint32_t i;

        uint32_t out_ptr = 0;
        while (outlen) {
            if (pos == r) {
                KeccakF1600_StatePermute(s);
                pos = 0;
            }
            for (i = pos; i < r && i < pos + outlen; i++)
                out[out_ptr++] = s[i / 8] >> 8 * (i % 8);
            outlen -= i - pos;
            pos = i;
        }

        return pos;
    }

    /*************************************************
    * Name:        shake256_squeeze
    *
    * Description: Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
    *              bytes. Can be called multiple times to keep squeezing.
    *
    * Arguments:   - uint8_t *out: pointer to output blocks
    *              - size_t outlen : number of bytes to be squeezed (written to output)
    *              - keccak_state *s: pointer to input/output Keccak state
    **************************************************/
    void shake256_squeeze(vector<uint8_t>& out, size_t outlen, keccak_state& state)
    {
        state.pos = keccak_squeeze(out, outlen, state.s, state.pos, SHAKE256_RATE);
    }

    /*************************************************
    * Name:        shake256
    *
    * Description: SHAKE256 XOF with non-incremental API
    *
    * Arguments:   - uint8_t *out: pointer to output
    *              - size_t outlen: requested output length in bytes
    *              - const uint8_t *in: pointer to input
    *              - size_t inlen: length of input in bytes
    **************************************************/
    void shake256(vector<uint8_t>& out, size_t outlen, vector<uint8_t>& in, size_t inlen)
    {
        size_t nblocks;
        keccak_state state;
        state.s.resize(25);

        shake256_absorb_once(state, in, inlen);
        nblocks = outlen / SHAKE256_RATE;
        shake256_squeezeblocks(out, nblocks, state);
        outlen -= nblocks * SHAKE256_RATE;
        vector<uint8_t> copy(out.begin() + nblocks * SHAKE256_RATE, out.end());
        out = copy;
        shake256_squeeze(out, outlen, state);
    }

    /*************************************************
    * Name:        kyber_shake256_prf
    *
    * Description: Usage of SHAKE256 as a PRF, concatenates secret and public input
    *              and then generates outlen bytes of SHAKE256 output
    *
    * Arguments:   - uint8_t *out: pointer to output
    *              - size_t outlen: number of requested output bytes
    *              - const uint8_t *key: pointer to the key (of length KYBER_SYMBYTES)
    *              - uint8_t nonce: single-byte nonce (public PRF input)
    **************************************************/
    void kyber_shake256_prf(vector<uint8_t>& out, size_t outlen, const vector<uint8_t>& key, uint8_t nonce)
    {
        vector<uint8_t> extkey(KYBER_SYMBYTES + 1);

        extkey.insert(extkey.begin(), key.begin(), key.begin() + KYBER_SYMBYTES);
        extkey.resize(KYBER_SYMBYTES + 1);
        extkey[KYBER_SYMBYTES] = nonce;

        shake256(out, outlen, extkey, sizeof(uint8_t) * (KYBER_SYMBYTES + 1));
    }

    /*************************************************
    * Name:        load32_littleendian
    *
    * Description: load 4 bytes into a 32-bit integer
    *              in little-endian order
    *
    * Arguments:   - const uint8_t *x: pointer to input byte array
    *
    * Returns 32-bit unsigned integer loaded from x
    **************************************************/
    static uint32_t load32_littleendian(const vector<uint8_t>& x)
    {
        uint32_t r;
        r = (uint32_t)x[0];
        r |= (uint32_t)x[1] << 8;
        r |= (uint32_t)x[2] << 16;
        r |= (uint32_t)x[3] << 24;
        return r;
    }

    /*************************************************
    * Name:        cbd2
    *
    * Description: Given an array of uniformly random bytes, compute
    *              polynomial with coefficients distributed according to
    *              a centered binomial distribution with parameter eta=2
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *buf: pointer to input byte array
    **************************************************/
    static void cbd2(poly& r, vector<uint8_t>& buf)
    {
        uint32_t i, j;
        uint32_t t, d;
        int16_t a, b;

        for (i = 0; i < KYBER_N / 8; i++) {
            vector<uint8_t> copy(buf.begin() + 4 * i, buf.end());
            t = load32_littleendian(copy);
            buf.insert(buf.begin() + 4 * i, copy.begin(), copy.end());
            buf.resize(4 * i + copy.size());
            d = t & 0x55555555;
            d += (t >> 1) & 0x55555555;

            for (j = 0; j < 8; j++) {
                a = (d >> (4 * j + 0)) & 0x3;
                b = (d >> (4 * j + 2)) & 0x3;
                r.coeffs[8 * i + j] = a - b;
            }
        }
    }

    void poly_cbd_eta1(poly& r, vector<uint8_t>& buf)
    {
        cbd2(r, buf);
    }

    /*************************************************
    * Name:        poly_getnoise_eta1
    *
    * Description: Sample a polynomial deterministically from a seed and a nonce,
    *              with output polynomial close to centered binomial distribution
    *              with parameter KYBER_ETA1
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *seed: pointer to input seed
    *                                     (of length KYBER_SYMBYTES bytes)
    *              - uint8_t nonce: one-byte input nonce
    **************************************************/
    void poly_getnoise_eta1(poly& r, const vector<uint8_t> seed, uint8_t nonce)
    {
        vector<uint8_t> buf(KYBER_ETA1 * KYBER_N / 4);
        prf(buf, sizeof(uint8_t) * (KYBER_ETA1 * KYBER_N / 4), seed, nonce);
        poly_cbd_eta1(r, buf);
    }

    /*************************************************
    * Name:        montgomery_reduce
    *
    * Description: Montgomery reduction; given a 32-bit integer a, computes
    *              16-bit integer congruent to a * R^-1 mod q, where R=2^16
    *
    * Arguments:   - int32_t a: input integer to be reduced;
    *                           has to be in {-q2^15,...,q2^15-1}
    *
    * Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
    **************************************************/
    int16_t montgomery_reduce(int32_t a)
    {
        int16_t t;

        t = static_cast<int16_t>(a) * QINV;
        t = (a - static_cast<int32_t>(t) * KYBER_Q) >> 16;
        return t;
    }

    /*************************************************
    * Name:        fqmul
    *
    * Description: Multiplication followed by Montgomery reduction
    *
    * Arguments:   - int16_t a: first factor
    *              - int16_t b: second factor
    *
    * Returns 16-bit integer congruent to a*b*R^{-1} mod q
    **************************************************/
    static int16_t fqmul(int16_t a, int16_t b) {
        return montgomery_reduce(static_cast<int32_t>(a) * b);
    }

    /*************************************************
    * Name:        ntt
    *
    * Description: Inplace number-theoretic transform (NTT) in Rq.
    *              input is in standard order, output is in bitreversed order
    *
    * Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
    **************************************************/
    void ntt(vector<int16_t>& r) {
        uint32_t len, start, j, k;
        int16_t t, zeta;

        k = 1;
        for (len = 128; len >= 2; len >>= 1) {
            for (start = 0; start < 256; start = j + len) {
                zeta = zetas[k++];
                for (j = start; j < start + len; j++) {
                    t = fqmul(zeta, r[j + len]);
                    r[j + len] = r[j] - t;
                    r[j] = r[j] + t;
                }
            }
        }
    }

    /*************************************************
    * Name:        barrett_reduce
    *
    * Description: Barrett reduction; given a 16-bit integer a, computes
    *              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
    *
    * Arguments:   - int16_t a: input integer to be reduced
    *
    * Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
    **************************************************/
    int16_t barrett_reduce(int16_t a) {
        int16_t t;
        const int16_t v = ((1 << 26) + KYBER_Q / 2) / KYBER_Q;

        t = (static_cast<int32_t>(v) * a + (1 << 25)) >> 26;
        t *= KYBER_Q;
        return a - t;
    }

    /*************************************************
    * Name:        poly_reduce
    *
    * Description: Applies Barrett reduction to all coefficients of a polynomial
    *              for details of the Barrett reduction see comments in reduce.c
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    void poly_reduce(poly& r)
    {
        uint32_t i;
        for (i = 0; i < KYBER_N; i++)
            r.coeffs[i] = barrett_reduce(r.coeffs[i]);
    }

    /*************************************************
    * Name:        poly_ntt
    *
    * Description: Computes negacyclic number-theoretic transform (NTT) of
    *              a polynomial in place;
    *              inputs assumed to be in normal order, output in bitreversed order
    *
    * Arguments:   - uint16_t *r: pointer to in/output polynomial
    **************************************************/
    void poly_ntt(poly& r)
    {
        ntt(r.coeffs);
        poly_reduce(r);
    }

    /*************************************************
    * Name:        polyvec_ntt
    *
    * Description: Apply forward NTT to all elements of a vector of polynomials
    *
    * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
    **************************************************/
    void polyvec_ntt(polyvec& r)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++)
            poly_ntt(r.vec[i]);
    }

    /*************************************************
    * Name:        basemul
    *
    * Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
    *              used for multiplication of elements in Rq in NTT domain
    *
    * Arguments:   - int16_t r[2]: pointer to the output polynomial
    *              - const int16_t a[2]: pointer to the first factor
    *              - const int16_t b[2]: pointer to the second factor
    *              - int16_t zeta: integer defining the reduction polynomial
    **************************************************/
    void basemul(vector<int16_t>& r, const vector<int16_t>& a, const vector<int16_t>& b, int16_t zeta)
    {
        r[0] = fqmul(a[1], b[1]);
        r[0] = fqmul(r[0], zeta);
        r[0] += fqmul(a[0], b[0]);
        r[1] = fqmul(a[0], b[1]);
        r[1] += fqmul(a[1], b[0]);
    }

    /*************************************************
    * Name:        poly_basemul_montgomery
    *
    * Description: Multiplication of two polynomials in NTT domain
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const poly *a: pointer to first input polynomial
    *              - const poly *b: pointer to second input polynomial
    **************************************************/
    void poly_basemul_montgomery(poly& r, poly& a, poly& b)
    {
        uint32_t i;
        for (i = 0; i < KYBER_N / 4; i++) {
            vector<int16_t> copyR(r.coeffs.begin() + 4 * i, r.coeffs.end());
            vector<int16_t> copyA(a.coeffs.begin() + 4 * i, a.coeffs.end());
            vector<int16_t> copyB(b.coeffs.begin() + 4 * i, b.coeffs.end());
            basemul(copyR, copyA, copyB, zetas[64 + i]);
            r.coeffs.insert(r.coeffs.begin() + 4 * i, copyR.begin(), copyR.end());
            r.coeffs.resize(4 * i + copyR.size());
            a.coeffs.insert(a.coeffs.begin() + 4 * i, copyA.begin(), copyA.end());
            a.coeffs.resize(4 * i + copyA.size());
            b.coeffs.insert(b.coeffs.begin() + 4 * i, copyB.begin(), copyB.end());
            b.coeffs.resize(4 * i + copyB.size());
            copyR.clear();
            copyA.clear();
            copyB.clear();
            copyR.insert(copyR.begin(), r.coeffs.begin() + 4 * i + 2, r.coeffs.end());
            copyA.insert(copyA.begin(), a.coeffs.begin() + 4 * i + 2, a.coeffs.end());
            copyB.insert(copyB.begin(), b.coeffs.begin() + 4 * i + 2, b.coeffs.end());
            basemul(copyR, copyA, copyB, -zetas[64 + i]);
            r.coeffs.insert(r.coeffs.begin() + 4 * i + 2, copyR.begin(), copyR.end());
            r.coeffs.resize(4 * i + 2 + copyR.size());
            a.coeffs.insert(a.coeffs.begin() + 4 * i + 2, copyA.begin(), copyA.end());
            a.coeffs.resize(4 * i + 2 + copyA.size());
            b.coeffs.insert(b.coeffs.begin() + 4 * i + 2, copyB.begin(), copyB.end());
            b.coeffs.resize(4 * i + 2 + copyB.size());
        }
    }

    /*************************************************
    * Name:        poly_add
    *
    * Description: Add two polynomials; no modular reduction is performed
    *
    * Arguments: - poly *r: pointer to output polynomial
    *            - const poly *a: pointer to first input polynomial
    *            - const poly *b: pointer to second input polynomial
    **************************************************/
    void poly_add(poly& r, const poly& a, const poly& b)
    {
        uint32_t i;
        for (i = 0; i < KYBER_N; i++)
            r.coeffs[i] = a.coeffs[i] + b.coeffs[i];
    }

    /*************************************************
    * Name:        polyvec_basemul_acc_montgomery
    *
    * Description: Multiply elements of a and b in NTT domain, accumulate into r,
    *              and multiply by 2^-16.
    *
    * Arguments: - poly *r: pointer to output polynomial
    *            - const polyvec *a: pointer to first input vector of polynomials
    *            - const polyvec *b: pointer to second input vector of polynomials
    **************************************************/
    void polyvec_basemul_acc_montgomery(poly& r, polyvec& a, polyvec& b)
    {
        uint32_t i;
        poly t;
        t.coeffs.resize(KYBER_N);

        poly_basemul_montgomery(r, a.vec[0], b.vec[0]);
        for (i = 1; i < KYBER_K; i++) {
            poly_basemul_montgomery(t, a.vec[i], b.vec[i]);
            poly_add(r, r, t);
        }

        poly_reduce(r);
    }

    /*************************************************
    * Name:        poly_tomont
    *
    * Description: Inplace conversion of all coefficients of a polynomial
    *              from normal domain to Montgomery domain
    *
    * Arguments:   - poly *r: pointer to input/output polynomial
    **************************************************/
    void poly_tomont(poly& r)
    {
        uint32_t i;
        const int16_t f = (1ULL << 32) % KYBER_Q;
        for (i = 0; i < KYBER_N; i++)
            r.coeffs[i] = montgomery_reduce(static_cast<int32_t>(r.coeffs[i]) * f);
    }

    /*************************************************
    * Name:        polyvec_add
    *
    * Description: Add vectors of polynomials
    *
    * Arguments: - polyvec *r: pointer to output vector of polynomials
    *            - const polyvec *a: pointer to first input vector of polynomials
    *            - const polyvec *b: pointer to second input vector of polynomials
    **************************************************/
    void polyvec_add(polyvec& r, const polyvec& a, const polyvec& b)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++)
            poly_add(r.vec[i], a.vec[i], b.vec[i]);
    }

    /*************************************************
    * Name:        polyvec_reduce
    *
    * Description: Applies Barrett reduction to each coefficient
    *              of each element of a vector of polynomials;
    *              for details of the Barrett reduction see comments in reduce.c
    *
    * Arguments:   - polyvec *r: pointer to input/output polynomial
    **************************************************/
    void polyvec_reduce(polyvec& r)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++)
            poly_reduce(r.vec[i]);
    }

    /*************************************************
    * Name:        poly_tobytes
    *
    * Description: Serialization of a polynomial
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (needs space for KYBER_POLYBYTES bytes)
    *              - const poly *a: pointer to input polynomial
    **************************************************/
    void poly_tobytes(vector<uint8_t>& r, const poly& a)
    {
        uint32_t i;
        uint16_t t0, t1;

        for (i = 0; i < KYBER_N / 2; i++) {
            // map to positive standard representatives
            t0 = a.coeffs[2 * i];
            t0 += (static_cast<int16_t>(t0) >> 15) & KYBER_Q;
            t1 = a.coeffs[2 * i + 1];
            t1 += (static_cast<int16_t>(t1) >> 15) & KYBER_Q;
            r[3 * i + 0] = (t0 >> 0);
            r[3 * i + 1] = (t0 >> 8) | (t1 << 4);
            r[3 * i + 2] = (t1 >> 4);
        }
    }

    /*************************************************
    * Name:        polyvec_tobytes
    *
    * Description: Serialize vector of polynomials
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (needs space for KYBER_POLYVECBYTES)
    *              - const polyvec *a: pointer to input vector of polynomials
    **************************************************/
    void polyvec_tobytes(vector<uint8_t>& r, const polyvec& a)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++) {
            vector<uint8_t> copy(r.begin() + i * KYBER_POLYBYTES, r.end());
            poly_tobytes(copy, a.vec[i]);
            r.insert(r.begin() + i * KYBER_POLYBYTES, copy.begin(), copy.end());
            r.resize(i * KYBER_POLYBYTES + copy.size());
        }
    }

    /*************************************************
    * Name:        sha3_256
    *
    * Description: SHA3-256 with non-incremental API
    *
    * Arguments:   - uint8_t *h: pointer to output (32 bytes)
    *              - const uint8_t *in: pointer to input
    *              - size_t inlen: length of input in bytes
    **************************************************/
    void sha3_256(vector<uint8_t>& h, vector<uint8_t>& in, size_t inlen)
    {
        uint32_t i;
        vector<uint64_t> s(25);

        keccak_absorb_once(s, SHA3_256_RATE, in, inlen, 0x06);
        KeccakF1600_StatePermute(s);
        for (i = 0; i < 4; i++) {
            vector<uint8_t> copy(h.begin() + 8 * i, h.end());
            store64(copy, s[i]);
            h.insert(h.begin() + 8 * i, copy.begin(), copy.end());
            h.resize(8 * i + copy.size());
        }
    }

    /*************************************************
    * Name:        poly_frombytes
    *
    * Description: De-serialization of a polynomial;
    *              inverse of poly_tobytes
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *a: pointer to input byte array
    *                                  (of KYBER_POLYBYTES bytes)
    **************************************************/
    void poly_frombytes(poly& r, const vector<uint8_t>& a)
    {
        uint32_t i;
        for (i = 0; i < KYBER_N / 2; i++) {
            r.coeffs[2 * i] = ((a[3 * i + 0] >> 0) | ((uint16_t)a[3 * i + 1] << 8)) & 0xFFF;
            r.coeffs[2 * i + 1] = ((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4)) & 0xFFF;
        }
    }

    /*************************************************
    * Name:        polyvec_frombytes
    *
    * Description: De-serialize vector of polynomials;
    *              inverse of polyvec_tobytes
    *
    * Arguments:   - uint8_t *r:       pointer to output byte array
    *              - const polyvec *a: pointer to input vector of polynomials
    *                                  (of length KYBER_POLYVECBYTES)
    **************************************************/
    void polyvec_frombytes(polyvec& r, vector<uint8_t>& a)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++) {
            vector<uint8_t> copy(a.begin() + i * KYBER_POLYBYTES, a.end());
            poly_frombytes(r.vec[i], copy);
            a.insert(a.begin() + i * KYBER_POLYBYTES, copy.begin(), copy.end());
            a.resize(i * KYBER_POLYBYTES + copy.size());
        }
    }

    /*************************************************
    * Name:        poly_frommsg
    *
    * Description: Convert 32-byte message to polynomial
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *msg: pointer to input message
    **************************************************/
    void poly_frommsg(poly& r, const vector<uint8_t>& msg)
    {
        uint32_t i, j;
        int16_t mask;

        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                mask = -(int16_t)((msg[i] >> j) & 1);
                r.coeffs[8 * i + j] = mask & ((KYBER_Q + 1) / 2);
            }
        }
    }

    void poly_cbd_eta2(poly& r, vector<uint8_t>& buf)
    {
        cbd2(r, buf);
    }

    /*************************************************
    * Name:        poly_getnoise_eta2
    *
    * Description: Sample a polynomial deterministically from a seed and a nonce,
    *              with output polynomial close to centered binomial distribution
    *              with parameter KYBER_ETA2
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *seed: pointer to input seed
    *                                     (of length KYBER_SYMBYTES bytes)
    *              - uint8_t nonce: one-byte input nonce
    **************************************************/
    void poly_getnoise_eta2(poly& r, const vector<uint8_t>& seed, uint8_t nonce)
    {
        vector<uint8_t> buf(KYBER_ETA2 * KYBER_N / 4);
        prf(buf, sizeof(uint8_t) * (KYBER_ETA2 * KYBER_N / 4), seed, nonce);
        poly_cbd_eta2(r, buf);
    }

    /*************************************************
    * Name:        invntt_tomont
    *
    * Description: Inplace inverse number-theoretic transform in Rq and
    *              multiplication by Montgomery factor 2^16.
    *              Input is in bitreversed order, output is in standard order
    *
    * Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
    **************************************************/
    void invntt(vector<int16_t>& r) {
        uint32_t start, len, j, k;
        int16_t t, zeta;
        const int16_t f = 1441; // mont^2/128

        k = 127;
        for (len = 2; len <= 128; len <<= 1) {
            for (start = 0; start < 256; start = j + len) {
                zeta = zetas[k--];
                for (j = start; j < start + len; j++) {
                    t = r[j];
                    r[j] = barrett_reduce(t + r[j + len]);
                    r[j + len] = r[j + len] - t;
                    r[j + len] = fqmul(zeta, r[j + len]);
                }
            }
        }

        for (j = 0; j < 256; j++)
            r[j] = fqmul(r[j], f);
    }

    /*************************************************
    * Name:        poly_invntt_tomont
    *
    * Description: Computes inverse of negacyclic number-theoretic transform (NTT)
    *              of a polynomial in place;
    *              inputs assumed to be in bitreversed order, output in normal order
    *
    * Arguments:   - uint16_t *a: pointer to in/output polynomial
    **************************************************/
    void poly_invntt_tomont(poly& r)
    {
        invntt(r.coeffs);
    }

    /*************************************************
    * Name:        polyvec_invntt_tomont
    *
    * Description: Apply inverse NTT to all elements of a vector of polynomials
    *              and multiply by Montgomery factor 2^16
    *
    * Arguments:   - polyvec *r: pointer to in/output vector of polynomials
    **************************************************/
    void polyvec_invntt_tomont(polyvec& r)
    {
        uint32_t i;
        for (i = 0; i < KYBER_K; i++)
            poly_invntt_tomont(r.vec[i]);
    }

    /*************************************************
    * Name:        polyvec_compress
    *
    * Description: Compress and serialize vector of polynomials
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
    *              - const polyvec *a: pointer to input vector of polynomials
    **************************************************/
    void polyvec_compress(vector<uint8_t>& r, const polyvec& a)
    {
        uint32_t i, j, k;

        vector<uint16_t> t(4);
        for (i = 0; i < KYBER_K; i++) {
            for (j = 0; j < KYBER_N / 4; j++) {
                for (k = 0; k < 4; k++) {
                    t[k] = a.vec[i].coeffs[4 * j + k];
                    t[k] += (static_cast<int16_t>(t[k]) >> 15) & KYBER_Q;
                    t[k] = (((static_cast<uint32_t>(t[k]) << 10) + KYBER_Q / 2) / KYBER_Q) & 0x3ff;
                }

                r[0] = (t[0] >> 0);
                r[1] = (t[0] >> 8) | (t[1] << 2);
                r[2] = (t[1] >> 6) | (t[2] << 4);
                r[3] = (t[2] >> 4) | (t[3] << 6);
                r[4] = (t[3] >> 2);
                vector<uint8_t> copy(r.begin() + 5, r.end());
                r = copy;
            }
        }
    }

    /*************************************************
    * Name:        poly_compress
    *
    * Description: Compression and subsequent serialization of a polynomial
    *
    * Arguments:   - uint8_t *r: pointer to output byte array
    *                            (of length KYBER_POLYCOMPRESSEDBYTES)
    *              - const poly *a: pointer to input polynomial
    **************************************************/
    void poly_compress(vector<uint8_t>& r, const poly& a)
    {
        uint32_t i, j;
        int16_t u;
        vector<uint8_t> t(8);

        for (i = 0; i < KYBER_N / 8; i++) {
            for (j = 0; j < 8; j++) {
                // map to positive standard representatives
                u = a.coeffs[8 * i + j];
                u += (u >> 15) & KYBER_Q;
                t[j] = ((((uint16_t)u << 4) + KYBER_Q / 2) / KYBER_Q) & 15;
            }

            r[0] = t[0] | (t[1] << 4);
            r[1] = t[2] | (t[3] << 4);
            r[2] = t[4] | (t[5] << 4);
            r[3] = t[6] | (t[7] << 4);
            vector<uint8_t> copy(r.begin() + 4, r.end());
            r = copy;
        }
    }

    /*************************************************
    * Name:        polyvec_decompress
    *
    * Description: De-serialize and decompress vector of polynomials;
    *              approximate inverse of polyvec_compress
    *
    * Arguments:   - polyvec *r:       pointer to output vector of polynomials
    *              - const uint8_t *a: pointer to input byte array
    *                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
    **************************************************/
    void polyvec_decompress(polyvec& r, vector<uint8_t>& a)
    {
        uint32_t i, j, k;

        uint16_t t[4];
        for (i = 0; i < KYBER_K; i++) {
            for (j = 0; j < KYBER_N / 4; j++) {
                t[0] = (a[0] >> 0) | ((uint16_t)a[1] << 8);
                t[1] = (a[1] >> 2) | ((uint16_t)a[2] << 6);
                t[2] = (a[2] >> 4) | ((uint16_t)a[3] << 4);
                t[3] = (a[3] >> 6) | ((uint16_t)a[4] << 2);
                vector<uint8_t> copy(a.begin() + 5, a.end());
                a = copy;

                for (k = 0; k < 4; k++)
                    r.vec[i].coeffs[4 * j + k] = ((uint32_t)(t[k] & 0x3FF) * KYBER_Q + 512) >> 10;
            }
        }

    }

    /*************************************************
    * Name:        poly_decompress
    *
    * Description: De-serialization and subsequent decompression of a polynomial;
    *              approximate inverse of poly_compress
    *
    * Arguments:   - poly *r: pointer to output polynomial
    *              - const uint8_t *a: pointer to input byte array
    *                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
    **************************************************/
    void poly_decompress(poly& r, vector<uint8_t>& a)
    {
        uint32_t i;

        for (i = 0; i < KYBER_N / 2; i++) {
            r.coeffs[2 * i + 0] = ((static_cast<uint16_t>(a[0] & 15) * KYBER_Q) + 8) >> 4;
            r.coeffs[2 * i + 1] = ((static_cast<uint16_t>(a[0] >> 4) * KYBER_Q) + 8) >> 4;
            vector<uint8_t> copy(a.begin() + 1, a.end());
            a = copy;
        }

    }

    /*************************************************
    * Name:        poly_sub
    *
    * Description: Subtract two polynomials; no modular reduction is performed
    *
    * Arguments: - poly *r:       pointer to output polynomial
    *            - const poly *a: pointer to first input polynomial
    *            - const poly *b: pointer to second input polynomial
    **************************************************/
    void poly_sub(poly& r, const poly& a, const poly& b)
    {
        uint32_t i;
        for (i = 0; i < KYBER_N; i++)
            r.coeffs[i] = a.coeffs[i] - b.coeffs[i];
    }

    /*************************************************
    * Name:        poly_tomsg
    *
    * Description: Convert polynomial to 32-byte message
    *
    * Arguments:   - uint8_t *msg: pointer to output message
    *              - const poly *a: pointer to input polynomial
    **************************************************/
    void poly_tomsg(vector<uint8_t>& msg, const poly& a)
    {
        uint32_t i, j;
        uint16_t t;

        for (i = 0; i < KYBER_N / 8; i++) {
            msg[i] = 0;
            for (j = 0; j < 8; j++) {
                t = a.coeffs[8 * i + j];
                t += (static_cast<int16_t>(t) >> 15) & KYBER_Q;
                t = (((t << 1) + KYBER_Q / 2) / KYBER_Q) & 1;
                msg[i] |= t << j;
            }
        }
    }

    /*************************************************
    * Name:        verify
    *
    * Description: Compare two arrays for equality in constant time.
    *
    * Arguments:   const uint8_t *a: pointer to first byte array
    *              const uint8_t *b: pointer to second byte array
    *              size_t len:       length of the byte arrays
    *
    * Returns 0 if the byte arrays are equal, 1 otherwise
    **************************************************/
    uint32_t verify(const vector<uint8_t>& a, const vector<uint8_t>& b, size_t len)
    {
        size_t i;
        uint8_t r = 0;

        for (i = 0; i < len; i++)
            r |= a[i] ^ b[i];

        return (-static_cast<int64_t>(r)) >> 63;
    }

    /*************************************************
    * Name:        cmov
    *
    * Description: Copy len bytes from x to r if b is 1;
    *              don't modify x if b is 0. Requires b to be in {0,1};
    *              assumes two's complement representation of negative integers.
    *              Runs in constant time.
    *
    * Arguments:   uint8_t *r:       pointer to output byte array
    *              const uint8_t *x: pointer to input byte array
    *              size_t len:       Amount of bytes to be copied
    *              uint8_t b:        Condition bit; has to be in {0,1}
    **************************************************/
    void cmov(vector<uint8_t>& r, const vector<uint8_t>& x, size_t len, uint8_t b)
    {
        size_t i;

        b = -b;
        for (i = 0; i < len; i++)
            r[i] ^= b & (r[i] ^ x[i]);
    }

}
