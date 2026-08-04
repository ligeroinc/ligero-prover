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

//! secp256k1, the Bitcoin and Ethereum curve.

use super::gen_table::{select_window, GEN_TABLE_WINDOWS};
use super::secp256k1_precomp::SECP256K1_G_PRECOMP;
use crate::ecc::coordinates::Affine;
use crate::ecc::curve::AffineCurve;
use crate::ecc::host::EccCurveType;
use crate::ecc::weierstrass::Weierstrass;
use crate::ff::FieldElement;
use crate::impl_prime_field;

/// secp256k1 base field, `p = 2^256 - 2^32 - 977`.
#[derive(Copy, Clone, Debug)]
pub struct Secp256k1Base;
impl_prime_field!(
    Secp256k1Base,
    "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
);

/// secp256k1 scalar field (the group order).
#[derive(Copy, Clone, Debug)]
pub struct Secp256k1Scalar;
impl_prime_field!(
    Secp256k1Scalar,
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
);

/// The secp256k1 curve, `y² = x³ + 7`.
pub struct Secp256k1 {
    form: Weierstrass<Secp256k1Base>,
    generator: Affine<Secp256k1Base>,
}

impl Default for Secp256k1 {
    fn default() -> Self {
        Self::new()
    }
}

impl Secp256k1 {
    pub fn new() -> Self {
        Self {
            form: Weierstrass::new(FieldElement::zero(), FieldElement::from_u32(7)),
            generator: Affine::new(
                FieldElement::from_str(
                    "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
                ),
                FieldElement::from_str(
                    "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
                ),
            ),
        }
    }
}

impl AffineCurve for Secp256k1 {
    type Base = Secp256k1Base;
    type Scalar = Secp256k1Scalar;
    type Form = Weierstrass<Secp256k1Base>;

    const CURVE_TYPE: EccCurveType = EccCurveType::Secp256k1;

    const ORDER_BE: &'static [u8; 32] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];

    const BASE_FIELD_BE: &'static [u8; 32] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff,
        0xfc, 0x2f,
    ];

    fn form(&self) -> &Weierstrass<Secp256k1Base> {
        &self.form
    }

    fn generator(&self) -> &Affine<Secp256k1Base> {
        &self.generator
    }

    fn scalar_mul_generator(&self, k: &FieldElement<Secp256k1Scalar>) -> Affine<Secp256k1Base> {
        let bits = k.to_bits();
        let mut acc = self.infinity().clone();
        for w in 0..GEN_TABLE_WINDOWS {
            let q = select_window::<Secp256k1Base>(&SECP256K1_G_PRECOMP, w, &bits);
            acc = self.point_add(&acc, &q);
        }
        acc
    }
}
