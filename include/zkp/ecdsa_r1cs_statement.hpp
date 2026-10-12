// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#pragma once

#include <algorithm>
#include <array>
#include <stdexcept>
#include <string_view>
#include <tuple>

#include <wabt/ir.h>
#include <zkp/hash.hpp>

namespace ligero::vm::zkp {

// Gate on the module, not a particular function or whether execution reaches it.
// Host calls are resolved from these static imports by the WASM runtime.
inline bool imports_ecdsa_r1cs(const wabt::Module& module) {
    return std::any_of(module.imports.begin(), module.imports.end(),
                       [](const wabt::Import* import) {
                           return import->module_name == "ecdsa_r1cs";
                       });
}

// Preserve historical transcripts for guests that do not opt into the new host.
// For opt-in guests, bind the exact bytes read from disk (WASM or WAT), the pinned
// circuit, and the already-computed public-input digest before Stage 1 challenges.
// The shape is 64 lowercase hexadecimal bytes; all remaining fields have fixed
// width. The domain includes its terminating NUL, as do existing stage domains.
template <IsHashScheme Hasher>
typename Hasher::digest bind_ecdsa_r1cs_statement(
    const wabt::Module& module,
    const typename Hasher::digest& program_hash,
    const typename Hasher::digest& public_input_hash,
    std::string_view circuit_shape) {
    if (!imports_ecdsa_r1cs(module)) return public_input_hash;

    if (circuit_shape.size() != 64 ||
        !std::all_of(circuit_shape.begin(), circuit_shape.end(), [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) {
        throw std::invalid_argument("ECDSA R1CS circuit shape must be 64 lowercase hex digits");
    }
    return hash<Hasher>(
        "LigetronEcdsaR1csStatementV1", program_hash,
        byte_view{reinterpret_cast<const uint8_t*>(circuit_shape.data()),
                  circuit_shape.size()},
        public_input_hash);
}

}  // namespace ligero::vm::zkp
