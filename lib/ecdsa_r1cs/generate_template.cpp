// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Build the public, immutable standard R1CS asset before deployment.
#include "template.hpp"
#include "circuit.hpp"

#include <chrono>
#include <iostream>

int main(int argc, char** argv) {
    try {
        if (argc == 3 && std::string_view(argv[1]) == "--validate") {
            const auto circuit = ligero::ecdsa_r1cs_host::load_fixed_circuit(argv[2]);
            std::cout << "Validated ECDSA R1CS template rows: " << circuit.rows.size() << '\n';
            return 0;
        }
        if (argc != 2) throw std::runtime_error("usage: generate_template OUTPUT_PREFIX");
        const auto started = std::chrono::steady_clock::now();
        const std::filesystem::path prefix(argv[1]);
        using namespace ecdsa_r1cs;
        const auto curve = curve_by_name("secp256k1");
        const Big digest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
        const auto key = native_mul(curve, Big(7), {curve.gx, curve.gy, false});
        const auto signature = native_sign(curve, digest, Big(7), Big(11));
        Builder builder(prefix);
        verify_ecdsa(builder, curve, digest, signature.first, signature.second, key);
        builder.finish();
        using namespace ligero::ecdsa_r1cs_host;
        if (builder.variables() != expected_variables || builder.constraints() != expected_rows ||
            builder.public_inputs() != 20 || builder.shape_hash() != expected_shape)
            throw std::runtime_error(
                "generated ECDSA R1CS template differs from pinned circuit: actual shape=" +
                builder.shape_hash() + ", rows=" + std::to_string(builder.constraints()) +
                ", variables=" + std::to_string(builder.variables()) +
                ", public_inputs=" + std::to_string(builder.public_inputs()) +
                "; expected shape=" + std::string(expected_shape) +
                ", rows=" + std::to_string(expected_rows) +
                ", variables=" + std::to_string(expected_variables) + ", public_inputs=20");
        const auto generated = std::chrono::steady_clock::now();
        const auto loaded = load_fixed_circuit(prefix.string() + ".r1cs");
        std::filesystem::remove(prefix.string() + ".wtns");
        std::cout << "ECDSA R1CS precompute generation seconds: "
                  << std::chrono::duration<double>(generated - started).count() << '\n'
                  << "ECDSA R1CS template-load seconds: "
                  << std::chrono::duration<double>(std::chrono::steady_clock::now() - generated).count() << '\n'
                  << "ECDSA R1CS template rows: " << loaded.rows.size() << '\n'
                  << "ECDSA R1CS template shape: " << builder.shape_hash() << '\n';
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
