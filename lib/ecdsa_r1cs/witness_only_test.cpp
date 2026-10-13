// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "circuit.hpp"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace ecdsa_r1cs;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void rejects(Function&& function) {
    try { function(); }
    catch (const std::runtime_error&) { return; }
    throw std::runtime_error("witness-only shape operation unexpectedly succeeded");
}

void check_api() {
    Builder fast(Builder::Mode::WitnessOnly);
    require(fast.witness_only(), "wrong builder mode");
    const auto a = fast.input(17);
    const auto b = fast.input(9);
    const auto product = fast.mul(a, b);
    fast.bits(product, 8);
    require(fast.value(product) == 153, "incorrect witness multiplication");
    // This is intentionally not a satisfaction check. The independently
    // enforced template is mandatory for every consumer of this mode.
    fast.equal(product, LC(154L));
    rejects([&] { fast.shape_hash(); });
    rejects([&] { fast.constraints(); });
    rejects([&] { fast.stage_counts(); });
    rejects([&] { fast.set_constraint_observer([](const LC&, const LC&, const LC&) {}); });
    rejects([&] { fast.bits(product, 7); });
    fast.finish();
    rejects([&] { fast.witness(1); });

    Builder checked;
    require(!checked.witness_only(), "default builder is not checked");
    rejects([&] { checked.equal(LC(153L), LC(154L)); });
    checked.input(17);
    rejects([&] { checked.append_witness_values({1}); });
    rejects([&] { checked.pad_witness_values(10); });

    Builder continuation(Builder::Mode::WitnessOnly);
    rejects([&] { continuation.append_witness_values({1}); });
    rejects([&] { continuation.pad_witness_values(10); });
    continuation.input(17);
    continuation.pad_witness_values(5);
    continuation.append_witness_values({9, native_modulus() - 1});
    require(continuation.witness_values() ==
        std::vector<Big>{1, 17, 0, 0, 0, 9, native_modulus() - 1},
        "witness continuation changed prefix or appended values");
    rejects([&] { continuation.input(11); });
    rejects([&] { continuation.pad_witness_values(6); });
    rejects([&] { continuation.pad_witness_values(uint64_t(UINT32_MAX) + 1); });
    rejects([&] { continuation.append_witness_values({-1}); });
    rejects([&] { continuation.append_witness_values({native_modulus()}); });
    rejects([&] { continuation.append_witness_values(continuation.witness_values()); });
    require(continuation.variables() == 7, "invalid continuation modified witness values");
    continuation.finish();
    rejects([&] { continuation.append_witness_values({1}); });
    rejects([&] { continuation.pad_witness_values(8); });
}

void check_range_only() {
    for (unsigned width = 0; width <= 200; ++width) {
        const Big limit = Big(1) << width;
        for (const Big& value : std::array<Big, 2>{Big(0), Big(limit - 1)}) {
            for (const bool constant : {false, true}) {
                Builder retained(Builder::Mode::WitnessOnly);
                Builder discarded(Builder::Mode::WitnessOnly);
                const LC a = constant ? LC(value) : retained.input(value);
                const LC b = constant ? LC(value) : discarded.input(value);
                const auto bits = retained.bits(a, width);
                discarded.range_check(b, width);
                require(retained.witness_values() == discarded.witness_values(),
                        "range-only expansion changed a bit value or wire position");
                for (unsigned i = 0; i < width; ++i)
                    require(retained.value(bits[i]) == (mpz_tstbit(value.get_mpz_t(), i) ? 1 : 0),
                            "retained bit expression changed");
                if (constant || width == 0) discarded.input(1);
                else rejects([&] { discarded.input(1); });
            }
        }
    }
    for (const unsigned width : {0u, 1u, 6u, 63u, 64u, 65u, 72u, 127u, 128u, 199u, 200u}) {
        for (const bool constant : {false, true}) {
            const Big value = (Big(1) << width) - 1;
            Builder retained, discarded;
            const LC a = constant ? LC(value) : retained.input(value);
            const LC b = constant ? LC(value) : discarded.input(value);
            retained.bits(a, width);
            discarded.range_check(b, width);
            require(retained.shape_hash() == discarded.shape_hash() &&
                    retained.witness_values() == discarded.witness_values(),
                    "range-only checked rows differ from ordinary bit decomposition");
        }
    }
    for (const auto mode : {Builder::Mode::Checked, Builder::Mode::WitnessOnly}) {
        Builder b(mode);
        b.range_check(LC(native_modulus()), 0);
        b.range_check(LC(native_modulus() + 1), 1);
        require(b.variables() == 1, "constant range check allocated bit witnesses");
        const LC input = b.input(1);
        rejects([&] { b.range_check(input, 0); });
        rejects([&] { b.range_check(input, 201); });
        rejects([&] { b.range_check(LC::wire(99), 1); });
        require(b.variables() == 2, "rejected range check modified witness values");
        b.finish();
        rejects([&] { b.range_check(input, 1); });
    }
}

void check_public_table_cache() {
    const auto curve = curve_by_name("secp256k1");
    Builder checked;
    CurveCircuit ec(checked, curve);
    const auto original_shape = checked.shape_hash();
    ec.prepare_fixed_base_table();
    require(checked.variables() == 1 && checked.constraints() == 0 &&
            checked.shape_hash() == original_shape,
            "public table preparation changed circuit or witness state");

    // The name alone must not identify a table. A different public generator
    // with the same curve name must obtain its own constants.
    auto alternate = curve;
    const auto doubled = native_mul(curve, Big(2), {curve.gx, curve.gy, false});
    alternate.gx = doubled.x;
    alternate.gy = doubled.y;
    Builder fast(Builder::Mode::WitnessOnly);
    CurveCircuit alternate_ec(fast, alternate);
    alternate_ec.prepare_fixed_base_table();
    ForeignField scalars(fast, alternate.n);
    const auto point = alternate_ec.fixed_mul(scalars.witness(1));
    require(!point.value.infinity && point.value.x == doubled.x && point.value.y == doubled.y,
            "public table cache did not distinguish complete curve parameters");
}

void check_fixture(const Curve& curve, const Big& digest, const Big& secret,
                   const Big& nonce, const std::string& label) {
    const auto key = native_mul(curve, secret, {curve.gx, curve.gy, false});
    const auto [r, s] = native_sign(curve, digest, secret, nonce);
    const auto started = std::chrono::steady_clock::now();
    Builder checked;
    verify_ecdsa(checked, curve, digest, r, s, key);
    checked.finish();
    const auto checked_end = std::chrono::steady_clock::now();
    Builder fast(Builder::Mode::WitnessOnly);
    verify_ecdsa(fast, curve, digest, r, s, key);
    fast.finish();
    const auto fast_end = std::chrono::steady_clock::now();
    require(checked.variables() == fast.variables(), "wire count changed");
    require(checked.public_inputs() == fast.public_inputs(), "input count changed");
    // Every checked row was evaluated on this exact vector. Equality proves
    // that fast mode preserved ALL auxiliaries, not only the visible outputs.
    require(checked.witness_values() == fast.witness_values(), "witness vector changed");
    if (curve.name == "secp256k1") {
        constexpr auto expected_shape =
            "44ce2b322d8f262076e543f7ca2f515e1325ad93a2db187dae63b13c608cf38f";
        require(checked.constraints() == 596424 && checked.variables() == 591290 &&
                checked.public_inputs() == 20 && checked.shape_hash() == expected_shape,
            "pinned secp256k1 circuit changed for " + label + ": actual shape=" +
            checked.shape_hash() + ", rows=" + std::to_string(checked.constraints()) +
            ", variables=" + std::to_string(checked.variables()) +
            ", public_inputs=" + std::to_string(checked.public_inputs()) +
            "; expected shape=" + expected_shape +
            ", rows=596424, variables=591290, public_inputs=20");
    }
    const double checked_seconds = std::chrono::duration<double>(checked_end - started).count();
    const double fast_seconds = std::chrono::duration<double>(fast_end - checked_end).count();
    std::cout << "{\"fixture\":\"" << curve.name << '/' << label
              << "\",\"checked_seconds\":" << checked_seconds
              << ",\"witness_only_seconds\":" << fast_seconds
              << ",\"speedup\":" << checked_seconds / fast_seconds
              << ",\"checked_rows\":" << checked.constraints()
              << ",\"equal_witness_values\":" << fast.variables() << "}\n";
}

} // namespace

int main() {
    try {
        check_api();
        check_range_only();
        const auto k1 = curve_by_name("secp256k1");
        const Big digest("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", 16);
        check_fixture(k1, digest, Big(7), Big(11), "public-template");
        check_fixture(k1, digest + 1, Big(13), Big(19), "alternate-key");
        check_fixture(k1, Big(0), Big(23), Big(29), "zero-digest");
        check_fixture(k1, mod(-2 * mod(k1.gx, k1.n), k1.n), Big(3), Big(1), "unit-u2");
        check_fixture(curve_by_name("p256"), digest, Big(7), Big(11), "p256-generic-builder");
        check_public_table_cache();
        std::cout << "PASS: checked and witness-only values agree; shape APIs fail closed\n";
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
