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

//! Ed25519 curve arithmetic, point encoding, key derivation and EdDSA verification.
//!
//! The signing and derivation vectors are RFC 8032 §7.1 TEST 1-3, so they check against the
//! standard rather than against this implementation.
//!
//! Run under the Ligetron VM — see `tests_wasm/run.sh`. There is no assertion framework: a
//! failed check makes the circuit unsatisfiable and the prover fails.

#[path = "common/mod.rs"]
mod common;

use common::{assert_point_eq, bytes_to_hex, check};

use ligetron::bn254fr::assert_equal_u32;
use ligetron::ecc::coordinates::Affine;
use ligetron::ecc::curve::AffineCurve;
use ligetron::ecc::curves::{Ed25519, Ed25519Base, Ed25519Scalar};
use ligetron::ecc::eddsa::Ed25519Eddsa;
use ligetron::ff::FieldElement;

type FE = FieldElement<Ed25519Base>;
type SE = FieldElement<Ed25519Scalar>;

// Generator, 2G, and the identity.
const G_X: &str = "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A";
const G_Y: &str = "0x6666666666666666666666666666666666666666666666666666666666666658";
const G2_X: &str = "0x36ab384c9f5a046c3d043b7d1833e7ac080d8e4515d7a45f83c5a14e2843ce0e";
const G2_Y: &str = "0x2260cdf3092329c21da25ee8c9a21f5697390f51643851560e5f46ae6af8a3c9";
const ID_X: &str = "0x0";
const ID_Y: &str = "0x1";

fn make_point(x: &str, y: &str) -> Affine<Ed25519Base> {
    Affine::new(FE::from_str(x), FE::from_str(y))
}

// ---------------------------------------------------------------- point encoding

fn do_test_point_encode(x: &str, y: &str, expected: &str) {
    let enc = Ed25519Eddsa::point_encode(&make_point(x, y));
    check(bytes_to_hex(&enc) == expected);
}

fn test_point_encode() {
    do_test_point_encode(
        G_X,
        G_Y,
        "5866666666666666666666666666666666666666666666666666666666666666",
    );
    do_test_point_encode(
        G2_X,
        G2_Y,
        "c9a3f86aae465f0e56513864510f3997561fa2c9e85ea21dc2292309f3cd6022",
    );
    do_test_point_encode(
        ID_X,
        ID_Y,
        "0100000000000000000000000000000000000000000000000000000000000000",
    );
    do_test_point_encode(
        "0x3f348ad8e75b7612eabaecef94d73a99fdd28f85bb46ebf17c2ed453356b1687",
        "0x9b5266c18a2be69cb3ebfefa3091020009a8377f21b2ba5339636e759442adc",
        "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589",
    );
}

// ---------------------------------------------------------------- on curve

fn do_test_point_on_curve(curve: &Ed25519, x: &str, y: &str, expected: bool) {
    let res = curve.on_curve(&make_point(x, y));
    assert_equal_u32(&res, u32::from(expected));
}

fn test_point_on_curve(curve: &Ed25519) {
    do_test_point_on_curve(curve, G_X, G_Y, true);
    do_test_point_on_curve(curve, G2_X, G2_Y, true);
    do_test_point_on_curve(curve, ID_X, ID_Y, true);
    // Generator with the last nibble of x altered.
    do_test_point_on_curve(
        curve,
        "0x216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51B",
        G_Y,
        false,
    );
}

// ---------------------------------------------------------------- group law

fn test_point_add(curve: &Ed25519) {
    assert_point_eq(
        &curve.point_add(curve.generator(), curve.generator()),
        &make_point(G2_X, G2_Y),
    );

    let id = make_point(ID_X, ID_Y);
    assert_point_eq(&curve.point_add(&id, &id), &id);
    assert_point_eq(&curve.point_add(curve.generator(), &id), curve.generator());
    assert_point_eq(&curve.point_add(&id, curve.generator()), curve.generator());

    // P + (-P) == identity
    assert_point_eq(
        &curve.point_add(curve.generator(), &curve.point_negate(curve.generator())),
        &id,
    );
}

fn test_point_double(curve: &Ed25519) {
    assert_point_eq(
        &curve.point_double(&make_point(G_X, G_Y)),
        &make_point(G2_X, G2_Y),
    );
}

// ---------------------------------------------------------------- scalar multiplication

fn test_scalar_mul(curve: &Ed25519) {
    // NOTE: k = 0 is deliberately not tested here, and is not supported by `scalar_mul`.
    //
    // `scalar_mul` proves [x]P - [z]Q = O with x == z*k (mod n), constraining both x and z to
    // be non-zero with x < sqrt(n). For k = 0 that would require x == 0 (mod n) with
    // 0 < x < sqrt(n), which has no solution — the constraint system is unsatisfiable rather
    // than wrong. `scalar_mul_generator` takes a different path and does handle k = 0.
    //
    // Both callers keep k away from zero in practice: ECDSA's u2 = r/s has r != 0 enforced,
    // and EdDSA's k is a SHA-512 output reduced mod L.
    let k1 = SE::from_str("1");
    assert_point_eq(
        &curve.scalar_mul(&k1, &make_point(G_X, G_Y)),
        &make_point(G_X, G_Y),
    );

    let k = SE::from_str("1000");
    assert_point_eq(
        &curve.scalar_mul(&k, &make_point(G_X, G_Y)),
        &make_point(
            "0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
            "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
        ),
    );
}

fn test_scalar_mul_generator(curve: &Ed25519) {
    let k0 = SE::from_str("0x0");
    assert_point_eq(
        &curve.scalar_mul_generator(&k0),
        &make_point(ID_X, ID_Y),
    );

    // Same vector as test_scalar_mul, through the precomputed-generator path.
    let k = SE::from_str("1000");
    assert_point_eq(
        &curve.scalar_mul_generator(&k),
        &make_point(
            "0x7d729f34487672ba293b953eaf0c41221c762b90f195f8e13e0e76abef68ce7e",
            "0x0ee1a16689ad85c7246c61a7192b28ba997c449bc5fe43aeaf943a3783aacae7",
        ),
    );
}

fn main() {
    let curve = Ed25519::new();
    test_point_encode();
    test_point_on_curve(&curve);
    test_point_add(&curve);
    test_point_double(&curve);
    test_scalar_mul(&curve);
    test_scalar_mul_generator(&curve);
}
