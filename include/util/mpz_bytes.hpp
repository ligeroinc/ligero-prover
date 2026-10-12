/* Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0. */
#pragma once

#include <bit>
#include <cstring>
#include <gmp.h>

namespace ligero::vm {

// GMP's public limb API exposes exactly the required bytes on little-endian,
// nail-free builds (both native 64-bit GMP and the wasm32 library). Keep the
// general importer for other representations and partial native limbs.
inline void mpz_import_words(mpz_ptr out, size_t count, size_t word_bytes,
                             int endian, const void* input) {
#if GMP_NAIL_BITS == 0
    if constexpr (std::endian::native == std::endian::little) {
        const size_t bytes = count * word_bytes;
        if (endian <= 0 && bytes != 0 && bytes % sizeof(mp_limb_t) == 0) {
            const size_t limbs = bytes / sizeof(mp_limb_t);
            auto* destination = mpz_limbs_write(out, limbs);
            std::memcpy(destination, input, bytes);
            mpz_limbs_finish(out, limbs);
            return;
        }
    }
#endif
    mpz_import(out, count, -1, word_bytes, endian, 0, input);
}

// The caller has already zero-filled the fixed-width output slot. Return the
// same number of significant output words as mpz_export, including for zero and
// negative inputs (mpz_export exports the magnitude).
inline size_t mpz_export_words(void* out, size_t word_bytes,
                              size_t capacity_words, mpz_srcptr value) {
#if GMP_NAIL_BITS == 0
    if constexpr (std::endian::native == std::endian::little) {
        const size_t limbs = mpz_size(value);
        const size_t bytes = limbs * sizeof(mp_limb_t);
        if (bytes <= capacity_words * word_bytes) {
            if (!limbs) return 0;
            std::memcpy(out, mpz_limbs_read(value), bytes);
            return (mpz_sizeinbase(value, 2) + 8 * word_bytes - 1) / (8 * word_bytes);
        }
    }
#endif
    size_t count = 0;
    mpz_export(out, &count, -1, word_bytes, -1, 0, value);
    return count;
}

} // namespace ligero::vm
