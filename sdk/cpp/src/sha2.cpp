/*
 * Copyright (C) 2023-2026 Ligero, Inc.
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

#include <ligetron/sha2.h>

/* macros */
#define S(x, n) (((((uint32_t)(x)&0xFFFFFFFFU)>>(uint32_t)((n)&31))|((uint32_t)(x)<<(uint32_t)((32-((n)&31))&31)))&0xFFFFFFFFU)
#define R(x, n) (((x)&0xFFFFFFFFU)>>(n))
#define Gamma0(x) (S(x, 7) ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x) (S(x, 17) ^ S(x, 19) ^ R(x, 10))
#define RND(a,b,c,d,e,f,g,h,i) \
    t0 = h + (S(e, 6) ^ S(e, 11) ^ S(e, 25)) + (g ^ (e & (f ^ g))) + K[i] + W[i]; \
    t1 = (S(a, 2) ^ S(a, 13) ^ S(a, 22)) + (((a | b) & c) | (a & b)); \
    d += t0; \
    h  = t0 + t1;
#define STORE32H(x, y) \
    (y)[0] = (unsigned char)(((x)>>24)&255); (y)[1] = (unsigned char)(((x)>>16)&255); \
    (y)[2] = (unsigned char)(((x)>>8)&255); (y)[3] = (unsigned char)((x)&255);
#define LOAD32H(x, y) \
    x = ((uint32_t)((y)[0]&255)<<24)|((uint32_t)((y)[1]&255)<<16)|((uint32_t)((y)[2]&255)<<8)|((uint32_t)((y)[3]&255));
// #define STORE64H(x, y) \
//     (y)[0] = (unsigned char)(((x)>>56)&255); (y)[1] = (unsigned char)(((x)>>48)&255); \
//     (y)[2] = (unsigned char)(((x)>>40)&255); (y)[3] = (unsigned char)(((x)>>32)&255); \
//     (y)[4] = (unsigned char)(((x)>>24)&255); (y)[5] = (unsigned char)(((x)>>16)&255); \
//     (y)[6] = (unsigned char)(((x)>>8)&255); (y)[7] = (unsigned char)((x)&255);
#define SHA256_COMPRESS(buff) \
    for (i = 0; i < 8; i++) S[i] = sha256_state[i]; \
    for (i = 0; i < 16; i++) LOAD32H(W[i], buff + (4*i)); \
    for (i = 16; i < 64; i++) W[i] = Gamma1(W[i-2]) + W[i-7] + Gamma0(W[i-15]) + W[i-16]; \
    for (i = 0; i < 64; i++) { \
        RND(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7],i); \
        t = S[7]; S[7] = S[6]; S[6] = S[5]; S[5] = S[4]; \
        S[4] = S[3]; S[3] = S[2]; S[2] = S[1]; S[1] = S[0]; S[0] = t; \
    } \
    for (i = 0; i < 8; i++) sha256_state[i] = sha256_state[i] + S[i];


constexpr unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

uint32_t ligetron_sha2_256 (unsigned char *out, const unsigned char* in, uint32_t len) {
    /* writes the sha256 hash of the first "len" bytes in buffer "in" to buffer "out"
     * returns 0 on success, may return non-zero in future versions to indicate error */
    uint32_t i;
    uint32_t sha256_length = 0;

    uint32_t sha256_state[8];
    sha256_state[0] = 0x6A09E667;
    sha256_state[1] = 0xBB67AE85;
    sha256_state[2] = 0x3C6EF372;
    sha256_state[3] = 0xA54FF53A;
    sha256_state[4] = 0x510E527F;
    sha256_state[5] = 0x9B05688C;
    sha256_state[6] = 0x1F83D9AB;
    sha256_state[7] = 0x5BE0CD19;

    uint32_t S[8], W[64];
    uint32_t t0, t1, t;
    unsigned char sha256_buf[64];

    /* process input in 64 byte chunks */
    while (len >= 64) {
       SHA256_COMPRESS(in);
       sha256_length += 64 * 8;
       in += 64;
       len -= 64;
    }
    /* copy remaining bytes into sha256_buf */
    for (int32_t i = 0; i < len; i++) {
        sha256_buf[i] = in[i];
    }
    // memcpy(sha256_buf, in, len);
    /* finish up (len now number of bytes in sha256_buf) */
    sha256_length += len * 8;
    sha256_buf[len++] = 0x80;
    /* pad then compress if length is above 56 bytes */
    if (len > 60) {
        while (len < 64) sha256_buf[len++] = 0;
        SHA256_COMPRESS(sha256_buf);
        len = 0;
    }
    /* pad up to 56 bytes */
    while (len < 60) sha256_buf[len++] = 0;

    /* store length and compress */
    // STORE64H(sha256_length, sha256_buf + 56);
    STORE32H(sha256_length, sha256_buf + 60);
    SHA256_COMPRESS(sha256_buf);

    /* copy output */
    for (i = 0; i < 8; i++) {
        STORE32H(sha256_state[i], out + 4*i);
    }

    /* return */
    return 0;
}
