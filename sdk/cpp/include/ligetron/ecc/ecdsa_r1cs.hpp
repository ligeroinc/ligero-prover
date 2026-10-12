// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include <ligetron/bn254fr.h>
#include <ligetron/apidef.h>

extern "C" {
// Import the versioned assert-valid, prehashed, low-S secp256k1 relation. The argument
// addresses twenty existing checked field handles; it is not a public-input
// array and never exports the key, signature, or digest.
LIGETRON_API(ecdsa_r1cs, assert_secp256k1_v1)
void ligetron_ecdsa_r1cs_assert_secp256k1(const bn254fr_t* limbs);
}

namespace ligetron::ecdsa_r1cs {

// Inputs are 32-byte big-endian integers. Signature s must already be low-s;
// normalizing (r,s) to (r,min(s,n-s)) before proving preserves ECDSA validity.
// This function constrains validity and returns no Boolean. It performs no
// hashing: the caller must constrain the digest to the intended message. The
// digest may be any unsigned 256-bit value. Public key coordinates must be
// canonical secp256k1 values; r must be in [1,n-1], s in [1,floor(n/2)].
// Each pointer addresses exactly 32 bytes in guest memory. Existing private
// bytes remain private; the wrapper binds checked field limbs to those bytes.
inline void assert_secp256k1(const unsigned char* public_x,
                         const unsigned char* public_y,
                         const unsigned char* signature_r,
                         const unsigned char* signature_s,
                         const unsigned char* digest) {
    const unsigned char* components[5] = {
        public_x, public_y, signature_r, signature_s, digest
    };
    bn254fr_t limbs[20];
    for (unsigned component = 0; component < 5; ++component) {
        for (unsigned limb = 0; limb < 4; ++limb) {
            const unsigned index = 4 * component + limb;
            bn254fr_alloc(limbs[index]);
            // Bind each handle to these exact existing guest bytes. R1CS input
            // range rows independently enforce that each value is 64 bits.
            bn254fr_set_bytes_checked(limbs[index],
                components[component] + 24 - 8 * limb, 8, 1);
        }
    }
    ligetron_ecdsa_r1cs_assert_secp256k1(limbs);
    // Handles are immutable after the host call and remain alive until it has
    // attached every defining equation. Preserve a deterministic release order.
    for (unsigned index = 20; index != 0; --index) {
        bn254fr_free(limbs[index - 1]);
    }
}

} // namespace ligetron::ecdsa_r1cs
