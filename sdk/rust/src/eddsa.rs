/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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

//! Edwards-curve Digital Signature Algorithm (EdDSA) for Ligetron
//!
//! ## Overview
//!
//! The EdDSA signature verification algorithm checks that:
//! **S·G = R + hash(R,A,M)·A**
//!
//! Where:
//! - G is the base point (generator) on the Baby Jubjub curve
//! - S is the signature scalar
//! - R is the signature point
//! - A is the public key point
//! - hash(R,A,M) is the challenge hash
//!
//! ```

use crate::babyjubjub::{JubjubPoint, JubjubPointVec};
use crate::bn254fr::Bn254Fr;
use crate::vbn254fr::VBn254Fr;

const GENERATOR_X: &str =
    "995203441582195749578291179787384436505546430278305826713579947235728471134";
const GENERATOR_Y: &str =
    "5472060717959818805561601436314318772137091100104008585924551046643952123905";

#[derive(Clone)]
pub struct EddsaSignature {
    pub r: JubjubPoint,
    pub s: Bn254Fr,
}

impl EddsaSignature {
    pub fn new(r: JubjubPoint, s: Bn254Fr) -> Self {
        EddsaSignature { r, s }
    }

    pub fn generator() -> JubjubPoint {
        JubjubPoint::new(
            Bn254Fr::from_str(GENERATOR_X),
            Bn254Fr::from_str(GENERATOR_Y),
        )
    }

    pub fn verify(sig: &mut EddsaSignature, public_key: &mut JubjubPoint, message: &mut Bn254Fr) {
        let g = Self::generator();

        let mut sg = g.scalar_mul(&sig.s);
        let mut p = public_key.scalar_mul(message);
        p = JubjubPoint::twisted_edward_add(&sig.r, &p);

        JubjubPoint::assert_equal(&mut sg, &mut p);
    }
}

#[derive(Clone)]
pub struct EddsaSignatureVec {
    pub r: JubjubPointVec,
    pub s: VBn254Fr,
}

impl EddsaSignatureVec {
    pub fn new(r: JubjubPointVec, s: VBn254Fr) -> Self {
        EddsaSignatureVec { r, s }
    }

    pub fn generator() -> JubjubPointVec {
        let x = VBn254Fr::from_str_scalar(GENERATOR_X);
        let y = VBn254Fr::from_str_scalar(GENERATOR_Y);
        JubjubPointVec::new(x, y)
    }

    pub fn verify(
        sig: &mut EddsaSignatureVec,
        public_key: &mut JubjubPointVec,
        message: &mut VBn254Fr,
    ) {
        let g = Self::generator();

        let mut sg = g.scalar_mul(&sig.s);
        let mut p = public_key.scalar_mul(message);
        p = JubjubPointVec::twisted_edward_add(&sig.r, &p);

        JubjubPointVec::assert_equal(&mut sg, &mut p);
    }
}
