// Copyright (C) 2026 Ligero, Inc. Licensed under Apache-2.0.
#include "circuit.hpp"

#include <array>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

using namespace ecdsa_r1cs;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error(message);
}

template <typename Function>
void expect_rejection(Function function, const std::string& message) {
    bool rejected = false;
    try { function(); }
    catch (const std::exception&) { rejected = true; }
    require(rejected, message);
}

Big circuit_integer(Builder& b, const Number& number) {
    Big value = 0;
    for (unsigned i = 0; i < 4; ++i) value += b.value(number.limbs[i]) << (64 * i);
    return value;
}

void check_number(Builder& b, const Number& result, const Big& expected,
                  const std::string& message) {
    require(result.value == expected, message + ": native witness value differs");
    require(circuit_integer(b, result) == expected, message + ": constrained limbs differ");
}

void check_point(Builder& b, const Point& point, const NativePoint& expected,
                 const std::string& message) {
    require(b.value(point.infinity) == (expected.infinity ? 1 : 0), message + ": infinity differs");
    const Big x = expected.infinity ? Big(0) : expected.x;
    const Big y = expected.infinity ? Big(0) : expected.y;
    check_number(b, point.x, x, message + ": x");
    check_number(b, point.y, y, message + ": y");
}

void arithmetic_bounds(const Big& modulus, const std::string& name) {
    Builder b;
    ForeignField f(b, modulus);
    const Big maximum = (Big(1) << 256) - 1;
    const std::vector<Big> boundaries{0, 1, (Big(1) << 64) - 1, Big(1) << 64,
                                     (Big(1) << 128) - 1, modulus / 2, modulus - 2, modulus - 1};
    Number denominator = f.witness(modulus - 1);
    for (const Big& a_value : boundaries) {
        Number a = f.witness(a_value);
        check_number(b, f.multiply(a, denominator), mod(-a_value, modulus), name + " multiply boundary");
        check_number(b, f.divide(a, denominator), mod(-a_value, modulus), name + " divide boundary");
        check_number(b, f.negate(a), mod(-a_value, modulus), name + " negate boundary");
    }

    // A raw digest is allowed to exceed the foreign modulus. Its limbs remain
    // bounded, and divide must reduce the mathematical value, not wrap in Fr.
    Number raw_maximum = f.bounded(maximum, 256);
    check_number(b, f.divide(raw_maximum, denominator), mod(-maximum, modulus), name + " maximum digest");

    Number large = f.witness(modulus - 1);
    LC negative = b.witness(1);
    b.bits(negative, 1);
    Number signed_large = f.signed_number(large, negative);
    Number positive_result = f.witness(mod(8 * large.value * large.value, modulus));
    Number negative_result = f.witness(mod(-8 * large.value * large.value, modulus));
    // Largest allowed product weight, both quotient signs, and signed limbs.
    f.relation({{8, &large, &large}}, {{-1, &positive_result}});
    f.relation({{-8, &large, &large}}, {{-1, &negative_result}});
    f.relation({{8, &signed_large, &large}}, {{-1, &negative_result}});
    f.relation({{8, &signed_large, &signed_large}}, {{-1, &positive_result}});

    Number one = f.constant(1);
    f.relation({}, {{8, &large}, {8, &one}});
    f.relation({}, {{-8, &large}, {-8, &one}});
    b.equal(f.equal(large, denominator), LC(1));
    b.equal(f.equal(large, one), LC(0));

    // A disabled relation imposes no equation on its bounded operands. This
    // is needed by the complete point-addition branch selectors.
    LC disabled = b.witness(0);
    b.bits(disabled, 1);
    f.relation({{8, &large, &large}}, {{16, &large}}, disabled);
    std::cout << name << ": " << b.constraints() << " arithmetic constraints checked\n";

    expect_rejection([&] { Builder bad; ForeignField ff(bad, modulus); ff.witness(modulus); },
                     name + ": noncanonical witness accepted");
    expect_rejection([&] { Builder bad; ForeignField ff(bad, modulus); ff.divide(ff.constant(1), ff.constant(0)); },
                     name + ": division by zero accepted");
    expect_rejection([&] {
        Builder bad;
        ForeignField ff(bad, modulus);
        Number a = ff.witness(modulus - 1);
        ff.relation({}, {{1, &a}});
    }, name + ": false modular relation accepted");
    expect_rejection([&] {
        Builder bad;
        ForeignField ff(bad, modulus);
        Number a = ff.constant(0);
        ff.relation({{9, &a, &a}}, {});
    }, name + ": unsupported product-weight bound accepted");
}

void comparison_boundaries() {
    const Curve curve = curve_by_name("secp256k1");
    const Big maximum = (Big(1) << 256) - 1;
    std::vector<Big> bounds{1, maximum, curve.p, curve.n,
                           curve_by_name("p256").p, curve_by_name("p256").n};
    for (unsigned bit : {1u, 3u, 4u, 63u, 64u, 127u, 128u, 191u, 255u}) {
        const Big power = Big(1) << bit;
        bounds.push_back(power);
        bounds.push_back(power - 1);
        bounds.push_back(power + 1);
    }
    for (const Big& bound : bounds) {
        for (const Big& value : std::vector<Big>{0, bound - 1}) {
            Builder b;
            ForeignField field(b, curve.p);
            field.canonical(field.bounded(value, 256), bound);
        }
        for (const Big& value : std::vector<Big>{bound, maximum})
            expect_rejection([&] {
                Builder b;
                ForeignField field(b, curve.p);
                field.canonical(field.bounded(value, 256), bound);
            }, "constant comparison accepted an out-of-range value");
    }
    std::cout << bounds.size() * 4 << " constant comparison boundaries checked\n";
}

void point_edges(const Curve& curve) {
    Builder b;
    CurveCircuit ec(b, curve);
    const NativePoint generator{curve.gx, curve.gy, false};
    const NativePoint infinity{0, 0, true};
    Point p = ec.point_witness(generator);
    Point zero = ec.point_witness(infinity);
    Point minus_p = ec.negate(p);
    check_point(b, ec.add(zero, zero), infinity, "O + O");
    check_point(b, ec.add(zero, p), generator, "O + P");
    check_point(b, ec.add(p, zero), generator, "P + O");
    check_point(b, ec.twice(zero), infinity, "2O");
    check_point(b, ec.add(p, minus_p), infinity, "P + (-P)");
    const NativePoint twice = native_add(curve, generator, generator);
    check_point(b, ec.twice(p), twice, "2P");
    check_point(b, ec.add(p, p), twice, "P + P");
    Point q = ec.point_witness(twice);
    check_point(b, ec.add(p, q), native_add(curve, generator, twice), "P + 2P");

    // Same opposite Y but different X is a finite sum. This catches the
    // incomplete unified-addition formula that confuses Y1+Y2=0 with P=-Q.
    bool found = false;
    for (unsigned k = 1; k <= 64 && !found; ++k) {
        NativePoint base = native_mul(curve, Big(k), generator);
        const Big discriminant = mod(-3 * base.x * base.x - 4 * curve.a, curve.p);
        Big root;
        const Big exponent = (curve.p + 1) / 4;
        mpz_powm(root.get_mpz_t(), discriminant.get_mpz_t(), exponent.get_mpz_t(), curve.p.get_mpz_t());
        if (mod(root * root, curve.p) != discriminant) continue;
        const Big alternative_x = mod((-base.x + root) * inverse(2, curve.p), curve.p);
        if (alternative_x == base.x) continue;
        NativePoint alternative{alternative_x, mod(-base.y, curve.p), false};
        Point first = ec.point_witness(base), second = ec.point_witness(alternative);
        NativePoint expected = native_add(curve, base, alternative);
        require(!expected.infinity, "opposite-Y distinct-X fixture unexpectedly infinite");
        check_point(b, ec.add(first, second), expected, "opposite Y with distinct X");
        found = true;
    }
    require(found, "could not construct opposite-Y distinct-X test vector");
    std::cout << curve.name << ": " << b.constraints() << " point-edge constraints checked\n";
}

void export_fixture(const std::filesystem::path& prefix) {
    const Curve curve = curve_by_name("secp256k1");
    const Big av = curve.p - 1, bv = curve.p - 2;
    const Big mask = (Big(1) << 64) - 1;
    Builder b(prefix);
    std::array<LC, 4> a_inputs, b_inputs;
    for (unsigned i = 0; i < 4; ++i) a_inputs[i] = b.input(Big((av >> (64 * i)) & mask));
    for (unsigned i = 0; i < 4; ++i) b_inputs[i] = b.input(Big((bv >> (64 * i)) & mask));
    ForeignField field(b, curve.p);
    Number a = field.from_inputs(a_inputs, av), c = field.from_inputs(b_inputs, bv);
    Number product = field.witness(2);
    const uint64_t quotient_first = b.variables();
    field.relation({{1, &a, &c}}, {{-1, &product}});
    // The relation allocates five quotient limbs and their bit witnesses,
    // sixteen nonconstant limb products, then three 72-bit carry witnesses.
    // Guard the indexing so this fixture cannot silently name the wrong
    // wires after a change to the relation implementation.
    const uint64_t quotient_last = quotient_first + 4 * 65;
    const uint64_t carry_first = quotient_first + 4 * 65 + 7 + 16;
    const uint64_t carry_last = carry_first + 2 * 73;
    require(b.variables() == carry_first + 3 * 73, "relation allocation layout changed");
    check_number(b, product, Big(2), "export fixture product");
    Number ratio = field.divide(product, c);
    b.equal(field.equal(ratio, a), LC(1));
    b.finish();
    std::cout << "export " << prefix << ": " << b.constraints() << " rows, "
              << b.variables() << " variables, shape " << b.shape_hash() << '\n';
    std::cout << "mutation wires: quotient_first=" << quotient_first
              << " quotient_last=" << quotient_last
              << " carry_first=" << carry_first
              << " carry_last=" << carry_last << '\n';
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc > 2) throw std::invalid_argument("usage: arithmetic_test [export-prefix]");
        comparison_boundaries();
        for (const std::string name : {"secp256k1", "p256"}) {
            Curve curve = curve_by_name(name);
            arithmetic_bounds(curve.p, name + "/base");
            arithmetic_bounds(curve.n, name + "/scalar");
            point_edges(curve);
        }
        if (argc == 2) export_fixture(argv[1]);
        std::cout << "arithmetic tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "arithmetic test failed: " << error.what() << '\n';
        return 1;
    }
}
