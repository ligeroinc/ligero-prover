/*
 * Copyright (C) 2023-2025 Soundness Labs.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ligetron/sha512.h>
#include <cstdint>
#include <cstring>

static const uint64_t PQCHAIN_SHA512_K[80] = {
    0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
    0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
    0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
    0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
    0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
    0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
    0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C898FB213FULL, 0xBF597FC7BEEF0EE4ULL,
    0xC6E00BF33DA88FC2ULL, 0xD5A79147930AA725ULL, 0x06CA6351E003826FULL, 0x142929670A0E6E70ULL,
    0x27B70A8546D22FFCULL, 0x2E1B21385C26C926ULL, 0x4D2C6DFC5AC42AEDULL, 0x53380D139D95B3DFULL,
    0x650A73548BAF63DEULL, 0x766A0ABB3C77B2A8ULL, 0x81C2C92E47EDAEE6ULL, 0x92722C851482353BULL,
    0xA2BFE8A14CF10364ULL, 0xA81A664BBC423001ULL, 0xC24B8B70D0F89791ULL, 0xC76C51A30654BE30ULL,
    0xD192E819D6EF5218ULL, 0xD69906245565A910ULL, 0xF40E35855771202AULL, 0x106AA07032BBD1B8ULL,
    0x19A4C116B8D2D0C8ULL, 0x1E376C085141AB53ULL, 0x2748774CDF8EEB99ULL, 0x34B0BCB5E19B48A8ULL,
    0x391C0CB3C5C95A63ULL, 0x4ED8AA4AE3418ACBULL, 0x5B9CCA4F7763E373ULL, 0x682E6FF3D6B2B8A3ULL,
    0x748F82EE5DEFB2FCULL, 0x78A5636F43172F60ULL, 0x84C87814A1F0AB72ULL, 0x8CC702081A6439ECULL,
    0x90BEFFFA23631E28ULL, 0xA4506CEBDE82BDE9ULL, 0xBEF9A3F7B2C67915ULL, 0xC67178F2E372532BULL,
    0xCA273ECEEA26619CULL, 0xD186B8C721C0C207ULL, 0xEADA7DD6CDE0EB1EULL, 0xF57D4F7FEE6ED178ULL,
    0x06F067AA72176FBAULL, 0x0A637DC5A2C898A6ULL, 0x113F9804BEF90DAEULL, 0x1B710B35131C471BULL,
    0x28DB77F523047D84ULL, 0x32CAAB7B40C72493ULL, 0x3C9EBE0A15C9BEBCULL, 0x431D67C49C100D4CULL,
    0x4CC5D4BECB3E42B6ULL, 0x597F299CFC657E2AULL, 0x5FCB6FAB3AD6FAECULL, 0x6C44198C4A475817ULL
};

#define PQCHAIN_S64(x, n) (((((uint64_t)(x)&0xFFFFFFFFFFFFFFFFULL)>>(uint64_t)((n)&63))|((uint64_t)(x)<<(uint64_t)((64-((n)&63))&63)))&0xFFFFFFFFFFFFFFFFULL)
#define PQCHAIN_R64(x, n) (((x)&0xFFFFFFFFFFFFFFFFULL)>>(n))
#define PQCHAIN_GAMMA0_64(x) (PQCHAIN_S64(x, 1) ^ PQCHAIN_S64(x, 8) ^ PQCHAIN_R64(x, 7))
#define PQCHAIN_GAMMA1_64(x) (PQCHAIN_S64(x, 19) ^ PQCHAIN_S64(x, 61) ^ PQCHAIN_R64(x, 6))
#define PQCHAIN_SHA512_ROUND(a,b,c,d,e,f,g,h,i) \
    sha_t0 = h + (PQCHAIN_S64(e, 14) ^ PQCHAIN_S64(e, 18) ^ PQCHAIN_S64(e, 41)) + (g ^ (e & (f ^ g))) + PQCHAIN_SHA512_K[i] + sha_W[i]; \
    sha_t1 = (PQCHAIN_S64(a, 28) ^ PQCHAIN_S64(a, 34) ^ PQCHAIN_S64(a, 39)) + (((a | b) & c) | (a & b)); \
    d += sha_t0; h = sha_t0 + sha_t1;
#define PQCHAIN_STORE64H(x, y) \
    (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
    (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
    (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
    (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255);
#define PQCHAIN_LOAD64H(x, y) \
    x = ((uint64_t)((y)[0]&255)<<56)|((uint64_t)((y)[1]&255)<<48)|((uint64_t)((y)[2]&255)<<40)|((uint64_t)((y)[3]&255)<<32)| \
        ((uint64_t)((y)[4]&255)<<24)|((uint64_t)((y)[5]&255)<<16)|((uint64_t)((y)[6]&255)<<8)|((uint64_t)((y)[7]&255));

static void pqchain_sha512_compress(uint64_t sha_state[8], const unsigned char* buff) {
    uint64_t sha_S[8], sha_W[80], sha_t0, sha_t1, sha_t;
    for (int i = 0; i < 8; i++) { sha_S[i] = 0ULL; }
    for (int i = 0; i < 80; i++) { sha_W[i] = 0ULL; }
    sha_t0 = 0ULL; sha_t1 = 0ULL; sha_t = 0ULL;

    for (int i = 0; i < 8; i++) sha_S[i] = sha_state[i];
    for (int i = 0; i < 16; i++) PQCHAIN_LOAD64H(sha_W[i], buff + (8*i));
    for (int i = 16; i < 80; i++) sha_W[i] = PQCHAIN_GAMMA1_64(sha_W[i-2]) + sha_W[i-7] + PQCHAIN_GAMMA0_64(sha_W[i-15]) + sha_W[i-16];
    for (int i = 0; i < 80; i++) {
        PQCHAIN_SHA512_ROUND(sha_S[0],sha_S[1],sha_S[2],sha_S[3],sha_S[4],sha_S[5],sha_S[6],sha_S[7],i);
        sha_t = sha_S[7]; sha_S[7] = sha_S[6]; sha_S[6] = sha_S[5]; sha_S[5] = sha_S[4];
        sha_S[4] = sha_S[3]; sha_S[3] = sha_S[2]; sha_S[2] = sha_S[1]; sha_S[1] = sha_S[0]; sha_S[0] = sha_t;
    }
    for (int i = 0; i < 8; i++) sha_state[i] = sha_state[i] + sha_S[i];
}

void ligetron_sha512(unsigned char *out, const unsigned char* in, int len) {
    uint64_t sha_len = 0;
    uint64_t sha_state[8];
    sha_state[0] = 0x6A09E667F3BCC908ULL; sha_state[1] = 0xBB67AE8584CAA73BULL;
    sha_state[2] = 0x3C6EF372FE94F82BULL; sha_state[3] = 0xA54FF53A5F1D36F1ULL;
    sha_state[4] = 0x510E527FADE682D1ULL; sha_state[5] = 0x9B05688C2B3E6C1FULL;
    sha_state[6] = 0x1F83D9ABFB41BD6BULL; sha_state[7] = 0x5BE0CD19137E2179ULL;
    unsigned char sha_buf[128];
    for (int i = 0; i < 128; i++) { sha_buf[i] = 0x00; }

    while (len >= 128) {
        pqchain_sha512_compress(sha_state, in);
        sha_len += 128 * 8; in += 128; len -= 128;
    }
    for (int i = 0; i < len; i++) { sha_buf[i] = in[i]; }
    sha_len += len * 8; sha_buf[len++] = 0x80;
    if (len > 112) {
        while (len < 128) { sha_buf[len++] = 0; }
        pqchain_sha512_compress(sha_state, sha_buf); len = 0;
    }
    while (len < 112) { sha_buf[len++] = 0; }
    PQCHAIN_STORE64H(0ULL, sha_buf + 112);
    PQCHAIN_STORE64H(sha_len, sha_buf + 120);
    pqchain_sha512_compress(sha_state, sha_buf);
    for (int i = 0; i < 8; i++) { PQCHAIN_STORE64H(sha_state[i], out + 8*i); }
}
