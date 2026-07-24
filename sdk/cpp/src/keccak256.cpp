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

/*
 * Keccak-256 as used by Ethereum (domain padding byte 0x01), not NIST
 * SHA3-256 (which pads with 0x06).
 */

#include <ligetron/keccak256.h>
#include <cstdint>

#define KECCAK256_RATE 136  /* bytes: 1088-bit rate, 512-bit capacity */

/* cyclic left rotate of a 64-bit lane */
#define KECCAK_ROTL64(x, y) (((x) << (y)) | ((x) >> (64 - (y))))

static const uint64_t keccakf_rndc[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

static void keccakf(uint64_t s[25]) {
    uint64_t t = 0ULL, bc[5];
    for (int i = 0; i < 5; i++) { bc[i] = 0ULL; }

    for (int round = 0; round < 24; round++) {
        /* Theta */
        for (int i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ KECCAK_ROTL64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }

        /* Rho Pi */
        t = s[1];
        for (int i = 0; i < 24; i++) {
            int j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = KECCAK_ROTL64(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for (int i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }
}

/* Keccak lanes are little-endian: byte j sits at bit 8*j. */
static uint64_t keccak_load64le(const unsigned char* b) {
    return ((uint64_t)(b[0] & 255))       | ((uint64_t)(b[1] & 255) << 8)  |
           ((uint64_t)(b[2] & 255) << 16) | ((uint64_t)(b[3] & 255) << 24) |
           ((uint64_t)(b[4] & 255) << 32) | ((uint64_t)(b[5] & 255) << 40) |
           ((uint64_t)(b[6] & 255) << 48) | ((uint64_t)(b[7] & 255) << 56);
}

static void keccak_store64le(unsigned char* b, uint64_t x) {
    b[0] = (unsigned char)(x & 255);         b[1] = (unsigned char)((x >> 8) & 255);
    b[2] = (unsigned char)((x >> 16) & 255); b[3] = (unsigned char)((x >> 24) & 255);
    b[4] = (unsigned char)((x >> 32) & 255); b[5] = (unsigned char)((x >> 40) & 255);
    b[6] = (unsigned char)((x >> 48) & 255); b[7] = (unsigned char)((x >> 56) & 255);
}

void ligetron_keccak256(unsigned char *out, const unsigned char* in, int len) {
    uint64_t s[25];
    for (int i = 0; i < 25; i++) { s[i] = 0ULL; }

    /* Absorb full rate-sized blocks (17 little-endian lanes each). */
    while (len >= KECCAK256_RATE) {
        for (int i = 0; i < KECCAK256_RATE / 8; i++)
            s[i] ^= keccak_load64le(in + 8 * i);
        keccakf(s);
        in += KECCAK256_RATE;
        len -= KECCAK256_RATE;
    }

    /* Final block: copy the tail, then pad10*1 (0x01 ... 0x80). */
    unsigned char buf[KECCAK256_RATE];
    for (int i = 0; i < KECCAK256_RATE; i++) { buf[i] = 0x00; }
    for (int i = 0; i < len; i++) { buf[i] = in[i]; }
    buf[len] = 0x01;
    buf[KECCAK256_RATE - 1] |= 0x80;
    for (int i = 0; i < KECCAK256_RATE / 8; i++)
        s[i] ^= keccak_load64le(buf + 8 * i);
    keccakf(s);

    /* Squeeze the first 256 bits = lanes s[0..3], little-endian. */
    for (int i = 0; i < 4; i++)
        keccak_store64le(out + 8 * i, s[i]);
}
