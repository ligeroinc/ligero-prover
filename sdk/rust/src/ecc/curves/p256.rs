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

//! NIST P-256 (secp256r1).

use super::gen_table::{select_window, GEN_TABLE_WINDOWS};
use super::p256_precomp::P256_G_PRECOMP;
use crate::ecc::coordinates::Affine;
use crate::ecc::curve::AffineCurve;
use crate::ecc::host::EccCurveType;
use crate::ecc::weierstrass::Weierstrass;
use crate::ff::FieldElement;
use crate::impl_prime_field;

/// P-256 base field, `p = 2^256 - 2^224 + 2^192 + 2^96 - 1`.
#[derive(Copy, Clone, Debug)]
pub struct P256Base;
impl_prime_field!(
    P256Base,
    "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff"
);

/// P-256 scalar field (the group order).
#[derive(Copy, Clone, Debug)]
pub struct P256Scalar;
impl_prime_field!(
    P256Scalar,
    "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
);

/// The P-256 curve.
pub struct P256 {
    form: Weierstrass<P256Base>,
    generator: Affine<P256Base>,
}

impl Default for P256 {
    fn default() -> Self {
        Self::new()
    }
}

impl P256 {
    pub fn new() -> Self {
        Self {
            form: Weierstrass::new(
                // a = p - 3
                FieldElement::from_str(
                    "0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
                ),
                FieldElement::from_str(
                    "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                ),
            ),
            generator: Affine::new(
                FieldElement::from_str(
                    "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                ),
                FieldElement::from_str(
                    "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                ),
            ),
        }
    }
}

impl AffineCurve for P256 {
    type Base = P256Base;
    type Scalar = P256Scalar;
    type Form = Weierstrass<P256Base>;

    const CURVE_TYPE: EccCurveType = EccCurveType::P256;

    const ORDER_BE: &'static [u8; 32] = &[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];

    const BASE_FIELD_BE: &'static [u8; 32] = &[
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff,
    ];

    fn form(&self) -> &Weierstrass<P256Base> {
        &self.form
    }

    fn generator(&self) -> &Affine<P256Base> {
        &self.generator
    }

    fn scalar_mul_generator(&self, k: &FieldElement<P256Scalar>) -> Affine<P256Base> {
        let bits = k.to_bits();
        // Weierstrass curves start from the identity sentinel and fold in all 32 windows.
        let mut acc = self.infinity().clone();
        for w in 0..GEN_TABLE_WINDOWS {
            let q = select_window::<P256Base>(&P256_G_PRECOMP, w, &bits);
            acc = self.point_add(&acc, &q);
        }
        acc
    }
}
