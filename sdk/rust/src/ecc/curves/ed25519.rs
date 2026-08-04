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

//! Ed25519, the twisted Edwards curve of RFC 8032.

use super::ed25519_precomp::ED25519_G_PRECOMP;
use super::gen_table::{select_window, GEN_TABLE_WINDOWS};
use crate::ecc::coordinates::Affine;
use crate::ecc::curve::AffineCurve;
use crate::ecc::host::EccCurveType;
use crate::ecc::twisted_edwards::Am1TwistedEdwards;
use crate::ff::FieldElement;
use crate::impl_prime_field;

/// Ed25519 base field, `p = 2^255 - 19`.
#[derive(Copy, Clone, Debug)]
pub struct Ed25519Base;
impl_prime_field!(
    Ed25519Base,
    "0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed"
);

/// Ed25519 scalar field (the prime-order subgroup order `L`).
#[derive(Copy, Clone, Debug)]
pub struct Ed25519Scalar;
impl_prime_field!(
    Ed25519Scalar,
    "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"
);

/// The Ed25519 curve.
pub struct Ed25519 {
    form: Am1TwistedEdwards<Ed25519Base>,
    generator: Affine<Ed25519Base>,
}

impl Default for Ed25519 {
    fn default() -> Self {
        Self::new()
    }
}

impl Ed25519 {
    pub fn new() -> Self {
        Self {
            form: Am1TwistedEdwards::new(FieldElement::from_str(
                "0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3",
            )),
            generator: Affine::new(
                FieldElement::from_str(
                    "0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a",
                ),
                FieldElement::from_str(
                    "0x6666666666666666666666666666666666666666666666666666666666666658",
                ),
            ),
        }
    }
}

impl AffineCurve for Ed25519 {
    type Base = Ed25519Base;
    type Scalar = Ed25519Scalar;
    type Form = Am1TwistedEdwards<Ed25519Base>;

    const CURVE_TYPE: EccCurveType = EccCurveType::Ed25519;

    const ORDER_BE: &'static [u8; 32] = &[
        0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5,
        0xd3, 0xed,
    ];

    const BASE_FIELD_BE: &'static [u8; 32] = &[
        0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xed,
    ];

    fn form(&self) -> &Am1TwistedEdwards<Ed25519Base> {
        &self.form
    }

    fn generator(&self) -> &Affine<Ed25519Base> {
        &self.generator
    }

    fn scalar_mul_generator(&self, k: &FieldElement<Ed25519Scalar>) -> Affine<Ed25519Base> {
        let bits = k.to_bits();
        // Unlike the Weierstrass curves this seeds from window 0 directly rather than from the
        // identity. Starting at the identity would add one redundant point addition and change
        // the constraint count.
        let mut acc = select_window::<Ed25519Base>(&ED25519_G_PRECOMP, 0, &bits);
        for w in 1..GEN_TABLE_WINDOWS {
            let q = select_window::<Ed25519Base>(&ED25519_G_PRECOMP, w, &bits);
            acc = self.point_add(&acc, &q);
        }
        acc
    }
}
