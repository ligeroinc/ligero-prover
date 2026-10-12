/* Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0. */
#include <array>
#include <iostream>
#include <random>
#include <stdexcept>
#include <vector>

#include <zkp/finite_field_gmp.hpp>

using Field = ligero::vm::zkp::bn254_gmp;
using Big = mpz_class;

namespace {
Big reference(const Big& x, const Big& y) {
    const Big& p = Field::modulus;
    return Big((Big(Big((x % p) * (y % p)) % p) + p) % p);
}

void require(const Big& value, const Big& expected) {
    if (value != expected || value < 0 || value >= Field::modulus)
        throw std::runtime_error("BN254 multiplication differs from modular reference");
}

void check(const Big& x, const Big& y) {
    const Big expected = reference(x, y);
    Big out = Big(1) << 1024, a = x, b = y;
    Field::mulmod(out, a, b);
    require(out, expected);
    Field::mulmod(a, a, b);
    require(a, expected);
    a = x;
    Field::mulmod(b, a, b);
    require(b, expected);
    a = x;
    Field::mulmod(a, a, a);
    require(a, reference(x, x));
}
} // namespace

int main() {
    try {
        const auto& p = Field::modulus;
        std::vector<Big> edges{0, 1, 2, p - 1, p, p + 1, 2 * p - 1,
                              -1, -p, 1 - p, (Big(1) << 256) - 1,
                              (Big(1) << 512) - 1};
        for (unsigned bits = 1; bits < 254; ++bits) {
            edges.emplace_back(Big(1) << bits);
            edges.emplace_back((Big(1) << bits) - 1);
        }
        for (const auto& x : edges)
            for (const auto& y : edges) check(x, y);

        std::mt19937_64 random(123);
        for (unsigned i = 0; i < 4096; ++i) {
            std::array<uint64_t, 8> words;
            Big x, y;
            for (auto& word : words) word = random();
            mpz_import(x.get_mpz_t(), words.size(), -1, sizeof(uint64_t), 0, 0, words.data());
            for (auto& word : words) word = random();
            mpz_import(y.get_mpz_t(), words.size(), -1, sizeof(uint64_t), 0, 0, words.data());
            check(x, y);
            check(Big(x % p), Big(y % p));
        }
        std::cout << "PASS: BN254 products, boundary values, and all output aliases\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
