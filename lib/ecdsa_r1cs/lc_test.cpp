// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
// Compare LC storage/arithmetic with an independent map-and-GMP reference.
#include "r1cs.hpp"

#include <array>
#include <iostream>
#include <map>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

using namespace ecdsa_r1cs;

namespace {
using Reference = std::map<std::uint32_t, Big>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

Big reduce(const Big& input) {
    Big result;
    mpz_mod(result.get_mpz_t(), input.get_mpz_t(), native_modulus().get_mpz_t());
    return result;
}

Reference normalize(const std::vector<Term>& terms) {
    Reference result;
    for (const auto& term : terms) result[term.wire] += term.coefficient;
    for (auto it = result.begin(); it != result.end();) {
        it->second = reduce(it->second);
        if (it->second == 0) it = result.erase(it);
        else ++it;
    }
    return result;
}

Reference combine(const Reference& a, const Reference& b, const Big& scale = Big(1)) {
    std::vector<Term> terms;
    for (const auto& [wire, coefficient] : a) terms.push_back({wire, coefficient});
    for (const auto& [wire, coefficient] : b) terms.push_back({wire, Big(coefficient * scale)});
    return normalize(terms);
}

Reference scaled(const Reference& value, const Big& scale) {
    return combine({}, value, scale);
}

void expect(const LC& actual, const Reference& expected) {
    const auto& terms = actual.terms();
    require(terms.size() == expected.size(), "LC term count differs from reference");
    auto reference = expected.begin();
    std::uint32_t previous = 0;
    for (std::size_t i = 0; i < terms.size(); ++i, ++reference) {
        const auto& term = terms[i];
        require(i == 0 || term.wire > previous, "LC wires are not strictly ordered");
        require(term.coefficient > 0 && term.coefficient < native_modulus(),
                "LC contains a zero or noncanonical coefficient");
        require(term.wire == reference->first && term.coefficient == reference->second,
                "LC coefficient differs from reference");
        previous = term.wire;
    }
    const auto constant = actual.constant();
    if (expected.empty()) {
        require(constant && *constant == 0, "empty LC is not constant zero");
    } else if (expected.size() == 1 && expected.begin()->first == 0) {
        require(constant && *constant == expected.begin()->second,
                "wire-zero LC is not the expected constant");
    } else {
        require(!constant, "nonconstant LC was classified as constant");
    }
}

Reference snapshot(const LC& value) {
    const auto& terms = value.terms();
    return normalize(std::vector<Term>(terms.begin(), terms.end()));
}

void check_arithmetic(const std::vector<Term>& left, const std::vector<Term>& right,
                      const Big& scalar) {
    const auto a_reference = normalize(left), b_reference = normalize(right);
    const LC a(left), b(right);
    expect(a, a_reference);
    expect(b, b_reference);
    expect(a + b, combine(a_reference, b_reference));
    expect(a - b, combine(a_reference, b_reference, Big(-1)));
    expect(-a, scaled(a_reference, Big(-1)));
    expect(a * scalar, scaled(a_reference, scalar));
    expect(scalar * a, scaled(a_reference, scalar));
    expect(a * 0L, {});
    expect(a * 1L, a_reference);
    expect(-1L * a, scaled(a_reference, Big(-1)));
    expect(a + a, scaled(a_reference, Big(2)));
    expect(a - a, {});
    expect(a + (b - a), b_reference);
    if (!a.terms().empty()) {
        // The scalar may be borrowed from the source LC itself.
        const Big& borrowed = a.terms().front().coefficient;
        expect(a * borrowed, scaled(a_reference, borrowed));
    }
    expect(a, a_reference);
    expect(b, b_reference);
}

void check_storage_transitions() {
    const std::vector<std::vector<Term>> inputs{
        {}, {{0, 1}}, {{9, 1}}, {{UINT32_MAX, native_modulus() - 1}},
        {{8, 2}, {0, -1}, {4, 3}}, {{0, 1}, {0, -1}, {7, 0}},
    };
    for (const auto& input : inputs) {
        const Reference reference = normalize(input);
        const LC original(input);
        // Borrowed views are checked only while their owner is unchanged.
        // Neither the old vector API nor the new span API promises stability
        // across assignment, move, or destruction of that owner.
        const auto& view = original.terms();
        const auto* original_data = view.data();
        LC copy(original);
        expect(copy, reference);
        if (!view.empty()) {
            require(copy.terms().data() != original_data, "copied LC shares term storage");
            require(view.front().coefficient == reference.begin()->second,
                    "copy construction changed a borrowed source view");
        }
        copy = copy;
        expect(copy, reference);
        LC moved(std::move(copy));
        expect(moved, reference);
        expect(copy, {});
        expect(copy + LC(1L), Reference{{0, Big(1)}});
        copy = original;
        expect(copy, reference);
        // A self-move must preserve a valid, canonical, reusable LC.
        copy = std::move(copy);
        expect(copy, snapshot(copy));
        copy = LC(5L);
        expect(copy, Reference{{0, Big(5)}});
        for (const auto& prior : inputs) {
            LC target(prior);
            target = original;
            expect(target, reference);
            LC source(original);
            target = std::move(source);
            expect(target, reference);
            expect(source, {});
            source = LC::wire(123);
            expect(source, Reference{{123, Big(1)}});
        }
        expect(original, reference);
    }

    // Exercise container relocation of empty, inline, and multi-term objects.
    std::vector<LC> values;
    for (unsigned i = 0; i < 200; ++i) values.emplace_back(inputs[i % inputs.size()]);
    for (unsigned i = 0; i < values.size(); ++i)
        expect(values[i], normalize(inputs[i % inputs.size()]));
}

Big random_integer(std::mt19937_64& random) {
    std::array<std::uint64_t, 4> words;
    for (auto& word : words) word = random();
    Big result;
    mpz_import(result.get_mpz_t(), words.size(), -1, sizeof(words[0]), 0, 0, words.data());
    if (random() & 1) result = -result;
    return result;
}

void run() {
    const Big& p = native_modulus();
    const std::array<Big, 11> scalars{Big(0), Big(1), Big(-1), p, p + 1, 1 - p,
        2 * p - 1, -2 * p, (Big(1) << 512) + 1, -(Big(1) << 512), p - 1};
    const std::vector<std::vector<Term>> edge_cases{
        {}, {{0, 0}}, {{0, 1}}, {{0, p}}, {{0, p + 1}}, {{0, -1}},
        {{1, 1}}, {{UINT32_MAX, 1}}, {{9, 1}, {9, -1}},
        {{2, 3}, {0, -1}, {2, p - 3}, {7, 0}, {0, 2}},
        {{2, -p}, {2, 2 * p}, {2, -p}, {1, (Big(1) << 512) + 7}},
        {{7, p - 1}, {3, 1}, {0, 2}, {7, 2}, {3, -1}},
    };
    for (const auto& value : scalars) expect(LC(value), normalize({{0, value}}));
    for (const auto& a : edge_cases)
        for (const auto& b : edge_cases)
            for (const auto& scalar : scalars) check_arithmetic(a, b, scalar);

    std::mt19937_64 random(0x6c696e656172ULL);
    for (unsigned trial = 0; trial < 2000; ++trial) {
        std::vector<Term> a, b;
        for (auto* terms : {&a, &b}) {
            const auto count = random() % 24;
            for (unsigned i = 0; i < count; ++i)
                terms->push_back({static_cast<std::uint32_t>(random() % 16), random_integer(random)});
        }
        check_arithmetic(a, b, random_integer(random));
    }
    check_storage_transitions();
}
} // namespace

int main() {
    try {
        run();
        std::cout << "PASS: canonical LC arithmetic, constants, copies, moves, and borrowed views\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
