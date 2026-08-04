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

//! P-256 curve arithmetic.

#[path = "common/mod.rs"]
mod common;

use common::assert_point_eq;

use ligetron::bn254fr::assert_equal_u32;
use ligetron::ecc::coordinates::Affine;
use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{P256Base, P256Scalar, P256};
use ligetron::ff::FieldElement;

type FE = FieldElement<P256Base>;
type SE = FieldElement<P256Scalar>;

// 2G, 3G and 4G on P-256.
const G2_X: &str = "0x7CF27B188D034F7E8A52380304B51AC3C08969E277F21B35A60B48FC47669978";
const G2_Y: &str = "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D1";
const G3_X: &str = "0x5ECBE4D1A6330A44C8F7EF951D4BF165E6C6B721EFADA985FB41661BC6E7FD6C";
const G3_Y: &str = "0x8734640C4998FF7E374B06CE1A64A2ECD82AB036384FB83D9A79B127A27D5032";
const G4_X: &str = "0xE2534A3532D08FBBA02DDE659EE62BD0031FE2DB785596EF509302446B030852";
const G4_Y: &str = "0xE0F1575A4C633CC719DFEE5FDA862D764EFC96C3F30EE0055C42C23F184ED8C6";

fn make_point(x: &str, y: &str) -> Affine<P256Base> {
    Affine::new(FE::from_str(x), FE::from_str(y))
}

fn test_point_add(curve: &P256) {
    // G + 2G == 3G
    assert_point_eq(
        &curve.point_add(curve.generator(), &make_point(G2_X, G2_Y)),
        &make_point(G3_X, G3_Y),
    );
}

fn test_point_double(curve: &P256) {
    // 2 * 2G == 4G
    assert_point_eq(
        &curve.point_double(&make_point(G2_X, G2_Y)),
        &make_point(G4_X, G4_Y),
    );
}

fn test_point_add_identity(curve: &P256) {
    // The identity is the (0:0) sentinel; adding it must be a no-op on both sides, and
    // O + O must stay O. The legacy `ec/` Weierstrass add got the two-sided case wrong, so
    // this is a regression guard rather than a formality.
    let o = curve.infinity();
    let g2 = make_point(G2_X, G2_Y);

    assert_point_eq(&curve.point_add(o, &g2), &g2);
    assert_point_eq(&curve.point_add(&g2, o), &g2);
    assert_point_eq(&curve.point_add(o, o), o);
}

fn test_point_add_negation(curve: &P256) {
    // P + (-P) == O. This is the case the legacy backend divided by zero on.
    let g2 = make_point(G2_X, G2_Y);
    assert_point_eq(
        &curve.point_add(&g2, &curve.point_negate(&g2)),
        curve.infinity(),
    );
}

fn test_scalar_mul(curve: &P256) {
    let k = SE::from_str("112233445566778899");
    assert_point_eq(
        &curve.scalar_mul(&k, curve.generator()),
        &make_point(
            "0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
            "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21",
        ),
    );
}

/// Small scalars, which the C++ suite never exercises on a Weierstrass curve.
///
/// `scalar_mul` builds its 4x4 precompute table with a guard that routes `prev == Q` to
/// `point_double` because `point_add` does not handle equal operands. For small `k` that guard
/// actually fires (traced for `k = 1` at index 13 and `k = 2` at index 14), and because
/// `select` evaluates both arms the rejected `point_add(Q, Q)` is still computed — with
/// `u1 = u2 = 0`, so its division degenerates to `0/0`.
///
/// That is benign rather than unsound: `div` obtains the quotient from unconstrained oracles
/// and then constrains `out * y == x`, which for `y = x = 0` is trivially satisfiable. But it
/// depends on `invmod_unchecked(0, p)` returning rather than trapping, and nothing else in
/// either test suite covers it. `p256_test.cpp` only uses a large `k`, and while
/// `ed25519_test.cpp` does test `k = 1`, Edwards addition is complete so the guard never
/// fires there.
fn test_scalar_mul_small_k(curve: &P256) {
    let g = curve.generator();

    let k1 = SE::from_str("1");
    assert_point_eq(&curve.scalar_mul(&k1, g), g);

    let k2 = SE::from_str("2");
    assert_point_eq(&curve.scalar_mul(&k2, g), &make_point(G2_X, G2_Y));

    let k3 = SE::from_str("3");
    assert_point_eq(&curve.scalar_mul(&k3, g), &make_point(G3_X, G3_Y));
}

fn test_scalar_mul_generator(curve: &P256) {
    // Same vector through the precomputed-generator path; the two must agree.
    let k = SE::from_str("112233445566778899");
    assert_point_eq(
        &curve.scalar_mul_generator(&k),
        &make_point(
            "0x339150844EC15234807FE862A86BE77977DBFB3AE3D96F4C22795513AEAAB82F",
            "0xB1C14DDFDC8EC1B2583F51E85A5EB3A155840F2034730E9B5ADA38B674336A21",
        ),
    );
}

fn test_on_curve(curve: &P256) {
    let good = curve.on_curve(&make_point(G2_X, G2_Y));
    assert_equal_u32(&good, 1);

    // 2G with y perturbed is not on the curve.
    let bad = curve.on_curve(&make_point(
        G2_X,
        "0x07775510DB8ED040293D9AC69F7430DBBA7DADE63CE982299E04B79D227873D2",
    ));
    assert_equal_u32(&bad, 0);
}

fn main() {
    let curve = P256::new();

    test_point_add(&curve);
    test_point_double(&curve);
    test_point_add_identity(&curve);
    test_point_add_negation(&curve);
    test_scalar_mul(&curve);
    test_scalar_mul_small_k(&curve);
    test_scalar_mul_generator(&curve);
    test_on_curve(&curve);
}
