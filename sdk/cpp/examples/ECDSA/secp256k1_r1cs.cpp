// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Arguments are decoded byte strings: public key X||Y (64 bytes), signature
// r||s (64 bytes, low-S), and a precomputed digest (32 bytes), all big-endian.
// This example proves validity for the supplied digest. Applications must also
// constrain their message hashing and any required ownership/authorization.
#include <ligetron/api.h>
#include <ligetron/ecc/ecdsa_r1cs.hpp>

#include <cstdio>
#include <cstdlib>

int main(int argc, char** argv) {
    if (argc != 4) {
        std::fprintf(stderr, "Expected public key, low-S signature, and digest\n");
        return EXIT_FAILURE;
    }
    int lengths[4];
    args_len_get(argv, lengths);
    if (lengths[1] != 64 || lengths[2] != 64 || lengths[3] != 32) {
        std::fprintf(stderr, "Expected argument lengths 64, 64, and 32 bytes\n");
        return EXIT_FAILURE;
    }
    const auto* key = reinterpret_cast<const unsigned char*>(argv[1]);
    const auto* signature = reinterpret_cast<const unsigned char*>(argv[2]);
    const auto* digest = reinterpret_cast<const unsigned char*>(argv[3]);
    ligetron::ecdsa_r1cs::assert_secp256k1(
        key, key + 32, signature, signature + 32, digest);
    return EXIT_SUCCESS;
}
