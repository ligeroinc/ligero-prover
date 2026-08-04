/*
 * Copyright (C) 2023-2026 Ligero, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * P-256 curve arithmetic tests.
 *
 * Reference values are small multiples of the standard generator, so each case is
 * checkable against any P-256 implementation.
 */

#include <ligetron/api.h>
#include <ligetron/ecc/curves/p256.hpp>
#include <string>

using namespace ligetron;
using namespace ligetron::ecc;

using curve_t   = curves::p256;
using point_t   = curve_t::point_type;
using f_element = curve_t::base_field_type;
using s_element = curve_t::scalar_field_type;

static const curve_t& curve() {
    static curve_t c;
    return c;
}

/// Asserts two points are equal. `operator==` returns a circuit value, so the comparison
/// is constrained rather than decided on the host.
static void assert_point_eq(const point_t& got, const point_t& exp) {
    auto eq = got == exp;
    bn254fr_assert_equal_u32(eq.data(), 1u);
}

static point_t make_point(const std::string& x_str, const std::string& y_str) {
    return point_t{f_element{x_str.c_str()}, f_element{y_str.c_str()}};
}

// 2G and 3G on P-256.
static const char* G2_X = "0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978";
static const char* G2_Y = "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1";
static const char* G3_X = "0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C";
static const char* G3_Y = "0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032";
static const char* G4_X = "0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852";
static const char* G4_Y = "0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6";

void test_point_add() {
    // G + 2G == 3G
    assert_point_eq(curve().point_add(curve().generator(), make_point(G2_X, G2_Y)),
                    make_point(G3_X, G3_Y));
}

void test_point_double() {
    // 2 * 2G == 4G
    assert_point_eq(curve().point_double(make_point(G2_X, G2_Y)), make_point(G4_X, G4_Y));
}

void test_point_add_identity() {
    // The identity is the (0:0) sentinel; adding it must be a no-op on both sides, and
    // O + O must stay O. `ec/`'s Weierstrass add got the two-sided case wrong, so this is
    // a regression guard rather than a formality.
    const point_t& O = curve().infinity();
    point_t g2 = make_point(G2_X, G2_Y);

    assert_point_eq(curve().point_add(O, g2), g2);
    assert_point_eq(curve().point_add(g2, O), g2);
    assert_point_eq(curve().point_add(O, O), O);
}

void test_point_add_negation() {
    // P + (-P) == O. This is the case `ec/` divided by zero on.
    point_t g2 = make_point(G2_X, G2_Y);
    assert_point_eq(curve().point_add(g2, curve().point_negate(g2)), curve().infinity());
}

void test_scalar_mul() {
    // k * G with k = 112233445566778899
    s_element k{"112233445566778899"};
    assert_point_eq(
        curve().scalar_mul(k, curve().generator()),
        make_point("0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
                   "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21"));
}

void test_scalar_mul_generator() {
    // Same vector through the precomputed-generator path; the two must agree.
    s_element k{"112233445566778899"};
    assert_point_eq(
        curve().scalar_mul_generator(k),
        make_point("0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
                   "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21"));
}

void test_on_curve() {
    // On-curve validation is what `ec/`'s Weierstrass backend lacked entirely.
    auto good = curve().on_curve(make_point(G2_X, G2_Y));
    bn254fr_assert_equal_u32(good.data(), 1u);

    // 2G with y perturbed is not on the curve.
    auto bad = curve().on_curve(
        make_point(G2_X, "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D2"));
    bn254fr_assert_equal_u32(bad.data(), 0u);
}

int main(int argc, char* argv[]) {
    test_point_add();
    test_point_double();
    test_point_add_identity();
    test_point_add_negation();
    test_scalar_mul();
    test_scalar_mul_generator();
    test_on_curve();

    return 0;
}
