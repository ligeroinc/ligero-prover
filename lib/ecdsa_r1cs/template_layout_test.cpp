// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Reconstruct the standard row serialization independently of compact storage.
#include "template.hpp"

#include <iostream>

void check_decoded_template(const std::filesystem::path& path) {
    using namespace ligero::ecdsa_r1cs_host;
    const auto circuit = load_fixed_circuit(path);
    std::vector<unsigned char> rows;
    rows.reserve(107102844);
    std::vector<std::uint32_t> last_use(expected_variables, UINT32_MAX);
    const auto append_u32 = [&](std::uint32_t value) {
        for (unsigned i = 0; i < 4; ++i) rows.push_back((value >> (8 * i)) & 255);
    };
    for (std::size_t i = 0; i < circuit.rows.size(); ++i) {
        for (const auto& expression : circuit.rows[i]) {
            const auto terms = circuit.terms(expression);
            append_u32(static_cast<std::uint32_t>(terms.size()));
            for (const auto& term : terms) {
                append_u32(term.wire);
                std::array<unsigned char, 32> bytes{};
                std::size_t size = 0;
                mpz_export(bytes.data(), &size, -1, 1, 0, 0,
                           circuit.coefficients[term.coefficient_index].get_mpz_t());
                rows.insert(rows.end(), bytes.begin(), bytes.end());
                last_use[term.wire] = static_cast<std::uint32_t>(i);
            }
        }
    }
    template_detail::validate_shape(rows);
    if (last_use != circuit.last_use)
        throw std::runtime_error("template last-use metadata differs from decoded rows");
    std::cout << "Validated compact template reconstructs the exact pinned rows and wire lifetimes\n";
}

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::runtime_error("usage: template_layout_test TEMPLATE_R1CS");
        check_decoded_template(argv[1]);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
