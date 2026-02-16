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

//! Baby Jubjub Elliptic Curve Operations for Ligetron
//!
//! ## Curve Forms
//!
//! ### Twisted Edwards Form (standard)
//! Equation: ax² + y² = 1 + dx²y²
//! - Parameters: a = 168700, d = 168696
//! - Generator: (995203441582195749578291179787384436505546430278305826713579947235728471134, 5472060717959818805561601436314318772137091100104008585924551046643952123905)
//! - Base Point: (5299619240641551281634865583518297030282874472190772894086521144482721001553, 16950150798460657717958625567821834550301663161624707787222815936182638968203)
//!
//! ### Montgomery Form
//! Equation: By² = x³ + Ax² + x
//! - Parameters: A = 168698, B = 1
//! - Generator: (7, 4258727773875940690362607550498304598101071202821725296872974770776423442226)
//! - Base Point: (7117928050407583618111176421555214756675765419608405867398403713213306743542, 14577268218881899420966779687690205425227431577728659819975198491127179315626)

use crate::bn254fr::{Bn254Fr, addmod_checked, submod_checked, mulmod_checked, divmod_checked, mux};
use crate::vbn254fr::{VBn254Fr, VBn254FrConstant, submod_vec, mulmod_vec, divmod_vec,
                     addmod_constant, submod_constant, mulmod_constant, constant_submod};
use lazy_static::lazy_static;

const COEF_A: &str = "168700";
const COEF_D: &str = "168696";
const COEF_MONT_A: &str = "168698";
const COEF_TWO_A: &str = "337396";

// Curve constants for vectorized implementation
lazy_static! {
    static ref VEC_ONE: VBn254FrConstant = VBn254FrConstant::from_str("1");
    static ref VEC_TWO: VBn254FrConstant = VBn254FrConstant::from_str("2");
    static ref VEC_THREE: VBn254FrConstant = VBn254FrConstant::from_str("3");
    static ref VEC_A: VBn254FrConstant = VBn254FrConstant::from_str(COEF_A);
    static ref VEC_D: VBn254FrConstant = VBn254FrConstant::from_str(COEF_D);
    static ref VEC_MONT_A: VBn254FrConstant = VBn254FrConstant::from_str(COEF_MONT_A);
    static ref VEC_TWO_A: VBn254FrConstant = VBn254FrConstant::from_str(COEF_TWO_A);
}

/// Baby Jubjub elliptic curve point
#[derive(Clone)]
pub struct JubjubPoint {
    pub x: Bn254Fr,
    pub y: Bn254Fr,
}

impl JubjubPoint {
    pub fn new(x: Bn254Fr, y: Bn254Fr) -> Self {
        JubjubPoint { x, y }
    }

    /// Create the identity point (0, 1) in Twisted Edwards form
    pub fn identity() -> Self {
        JubjubPoint {
            x: Bn254Fr::from_u32(0),
            y: Bn254Fr::from_u32(1),
        }
    }

    pub fn assert_equal(p: &mut JubjubPoint, q: &mut JubjubPoint) {
        Bn254Fr::assert_equal(&mut p.x, &mut q.x);
        Bn254Fr::assert_equal(&mut p.y, &mut q.y);
    }

    /// Conditional selection between two points
    pub fn mux(cond: &Bn254Fr, b0: &JubjubPoint, b1: &JubjubPoint) -> JubjubPoint {
        let mut result = JubjubPoint::new(Bn254Fr::new(), Bn254Fr::new());
        mux(&mut result.x, cond, &b0.x, &b1.x);
        mux(&mut result.y, cond, &b0.y, &b1.y);
        result
    }

    /// 4-way conditional selection
    /// Selects one of four points based on two selector bits
    pub fn mux2(s0: &Bn254Fr, s1: &Bn254Fr,
                b0: &JubjubPoint, b1: &JubjubPoint,
                b2: &JubjubPoint, b3: &JubjubPoint) -> JubjubPoint {
        let mut result = JubjubPoint::new(Bn254Fr::new(), Bn254Fr::new());
        crate::bn254fr::mux2(&mut result.x, s0, s1, &b0.x, &b1.x, &b2.x, &b3.x);
        crate::bn254fr::mux2(&mut result.y, s0, s1, &b0.y, &b1.y, &b2.y, &b3.y);
        result
    }

    /// Convert from Twisted Edwards to Montgomery form
    /// TE -> Montgomery: u = (1+y)/(1-y), v = (1-y)/(x*(1+y))
    pub fn to_montgomery(&self) -> JubjubPoint {
        let mut one_plus_y = Bn254Fr::new();
        let mut one_minus_y = Bn254Fr::new();
        let one = Bn254Fr::from_u32(1);

        addmod_checked(&mut one_plus_y, &one, &self.y);
        submod_checked(&mut one_minus_y, &one, &self.y);

        let mut mnt = JubjubPoint::new(Bn254Fr::new(), Bn254Fr::new());
        divmod_checked(&mut mnt.x, &one_plus_y, &one_minus_y);

        let mut temp = Bn254Fr::new();
        mulmod_checked(&mut temp, &one_minus_y, &self.x);
        divmod_checked(&mut mnt.y, &one_plus_y, &temp);

        mnt
    }

    /// Convert from Montgomery to Twisted Edwards form
    /// Montgomery -> TE: x = u/v, y = (u-1)/(u+1)
    pub fn to_twisted_edward(&self) -> JubjubPoint {
        let one = Bn254Fr::from_u32(1);
        let mut ted = JubjubPoint::new(Bn254Fr::new(), Bn254Fr::new());

        divmod_checked(&mut ted.x, &self.x, &self.y);

        let mut temp = Bn254Fr::new();
        submod_checked(&mut ted.y, &self.x, &one);
        addmod_checked(&mut temp, &self.x, &one);
        ted.y.divmod_checked(&temp);

        ted
    }

    /// Twisted Edwards point addition
    /// Formula: ((x1*y2 + y1*x2)/(1 + d*x1*x2*y1*y2), (y1*y2 - a*x1*x2)/(1 - d*x1*x2*y1*y2))
    pub fn twisted_edward_add(a: &JubjubPoint, b: &JubjubPoint) -> JubjubPoint {
        let one = Bn254Fr::from_u32(1);
        let coeff_te_a = Bn254Fr::from_str(COEF_A);  // Twisted Edwards parameter a
        let coeff_te_d = Bn254Fr::from_str(COEF_D);  // Twisted Edwards parameter d
        let mut lambda = Bn254Fr::new();

        mulmod_checked(&mut lambda, &coeff_te_d, &a.x);
        lambda.mulmod_checked(&a.y);
        lambda.mulmod_checked(&b.x);
        lambda.mulmod_checked(&b.y);

        let mut t1 = Bn254Fr::new();
        let mut t2 = Bn254Fr::new();
        let mut t3 = Bn254Fr::new();

        mulmod_checked(&mut t1, &a.x, &b.y);
        mulmod_checked(&mut t2, &a.y, &b.x);
        addmod_checked(&mut t3, &one, &lambda);

        t1.addmod_checked(&t2);
        let mut result_x = Bn254Fr::new();
        divmod_checked(&mut result_x, &t1, &t3);

        mulmod_checked(&mut t1, &a.y, &b.y);
        mulmod_checked(&mut t2, &a.x, &b.x);
        let t2_temp = t2.clone();
        mulmod_checked(&mut t2, &coeff_te_a, &t2_temp);
        submod_checked(&mut t3, &one, &lambda);

        t1.submod_checked(&t2);
        let mut result_y = Bn254Fr::new();
        divmod_checked(&mut result_y, &t1, &t3);

        JubjubPoint::new(result_x, result_y)
    }

    /// Montgomery point doubling
    /// Uses Montgomery form for efficient doubling operation
    pub fn montgomery_double(p: &JubjubPoint) -> JubjubPoint {
        let one = Bn254Fr::from_u32(1);
        let coeff_mont_a = Bn254Fr::from_str(COEF_MONT_A);   // Montgomery parameter A
        let mut result = JubjubPoint::new(Bn254Fr::new(), Bn254Fr::new());

        // Calculate lambda = (3x² + 2Ax + 1) / (2y)
        let mut lam = Bn254Fr::from_u32(3);
        lam.mulmod_checked(&p.x);
        lam.mulmod_checked(&p.x);

        let mut t1 = Bn254Fr::from_str(COEF_TWO_A);
        t1.mulmod_checked(&p.x);

        lam.addmod_checked(&t1);
        lam.addmod_checked(&one);

        let mut t2 = Bn254Fr::from_u32(2);
        t2.mulmod_checked(&p.y);

        lam.divmod_checked(&t2);

        // x₂ = λ² - 2x - A
        let mut t4 = Bn254Fr::from_u32(2);
        mulmod_checked(&mut result.x, &lam, &lam);
        t4.mulmod_checked(&p.x);
        result.x.submod_checked(&t4);
        result.x.submod_checked(&coeff_mont_a);

        // y₂ = λ(x - x₂) - y
        let mut t5 = Bn254Fr::new();
        submod_checked(&mut t5, &p.x, &result.x);
        mulmod_checked(&mut result.y, &lam, &t5);
        result.y.submod_checked(&p.y);

        result
    }

    /// Scalar multiplication using windowing method
    /// Multiplies this point by scalar x using 2-bit windows
    pub fn scalar_mul(&self, x: &Bn254Fr) -> JubjubPoint {

        let w0 = JubjubPoint::identity();
        let w1 = self.clone();
        let w2 = JubjubPoint::twisted_edward_add(self, self);
        let w3 = JubjubPoint::twisted_edward_add(&w1, &w2);

        let bits = x.to_bits(254);

        let mut acc = JubjubPoint::mux2(&bits[252], &bits[253], &w0, &w1, &w2, &w3);

        for i in (0..251).step_by(2).rev() {
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);

            let temp = JubjubPoint::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3);
            acc = JubjubPoint::twisted_edward_add(&acc, &temp);
        }

        acc
    }

    /// Extended scalar multiplication with two scalars
    /// Computes x1*G + x2*H where G is this point and H is computed from x2
    pub fn scalar_mul_extend(&self, x1: &Bn254Fr, x2: &Bn254Fr) -> JubjubPoint {
        let w0 = JubjubPoint::identity();
        let w1 = self.clone();
        let w2 = JubjubPoint::twisted_edward_add(self, self);
        let w3 = JubjubPoint::twisted_edward_add(&w1, &w2);

        // Process x2 first
        let mut bits = x2.to_bits(254);
        let mut acc = JubjubPoint::mux2(&bits[252], &bits[253], &w0, &w1, &w2, &w3);

        for i in (0..251).step_by(2).rev() {
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);

            let temp = JubjubPoint::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3);
            acc = JubjubPoint::twisted_edward_add(&acc, &temp);
        }

        // Process x1
        bits = x1.to_bits(254);
        for i in (0..253).step_by(2).rev() {
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);
            acc = JubjubPoint::twisted_edward_add(&acc, &acc);

            let temp = JubjubPoint::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3);
            acc = JubjubPoint::twisted_edward_add(&acc, &temp);
        }

        acc
    }
}

/// Baby Jubjub elliptic curve point using vectorized field arithmetic
#[derive(Clone)]
pub struct JubjubPointVec {
    pub x: VBn254Fr,
    pub y: VBn254Fr,
}

impl JubjubPointVec {
    pub fn new(x: VBn254Fr, y: VBn254Fr) -> Self {
        JubjubPointVec { x, y }
    }

    /// Create the identity point (0, 1) in Twisted Edwards form
    pub fn identity() -> Self {
        let mut x = VBn254Fr::new();
        let mut y = VBn254Fr::new();
        x.set_ui_scalar(0);
        y.set_ui_scalar(1);
        JubjubPointVec { x, y }
    }

    pub fn assert_equal(p: &mut JubjubPointVec, q: &mut JubjubPointVec) {
        VBn254Fr::assert_equal(&mut p.x, &mut q.x);
        VBn254Fr::assert_equal(&mut p.y, &mut q.y);
    }

    /// Conditional selection between two vectorized points
    pub fn mux(cond: &VBn254Fr, b0: &JubjubPointVec, b1: &JubjubPointVec) -> JubjubPointVec {
        let mut result = JubjubPointVec::new(VBn254Fr::new(), VBn254Fr::new());
        crate::vbn254fr::mux_vec(&mut result.x, cond, &b0.x, &b1.x);
        crate::vbn254fr::mux_vec(&mut result.y, cond, &b0.y, &b1.y);
        result
    }

    /// 4-way conditional selection for vectorized points
    pub fn mux2(s0: &VBn254Fr, s1: &VBn254Fr,
                b0: &JubjubPointVec, b1: &JubjubPointVec,
                b2: &JubjubPointVec, b3: &JubjubPointVec) -> JubjubPointVec {
        let mut result = JubjubPointVec::new(VBn254Fr::new(), VBn254Fr::new());
        crate::vbn254fr::mux2_vec(&mut result.x, s0, s1, &b0.x, &b1.x, &b2.x, &b3.x);
        crate::vbn254fr::mux2_vec(&mut result.y, s0, s1, &b0.y, &b1.y, &b2.y, &b3.y);
        result
    }

    /// Convert from Twisted Edwards to Montgomery form (vectorized)
    pub fn to_montgomery(&self) -> JubjubPointVec {
        let mut one_plus_y = VBn254Fr::new();
        let mut one_minus_y = VBn254Fr::new();

        addmod_constant(&mut one_plus_y, &self.y, &VEC_ONE);
        constant_submod(&mut one_minus_y, &VEC_ONE, &self.y);

        let mut mnt = JubjubPointVec::new(VBn254Fr::new(), VBn254Fr::new());
        divmod_vec(&mut mnt.x, &one_plus_y, &one_minus_y);

        let mut temp = VBn254Fr::new();
        mulmod_vec(&mut temp, &one_minus_y, &self.x);
        divmod_vec(&mut mnt.y, &one_plus_y, &temp);

        mnt
    }

    /// Convert from Montgomery to Twisted Edwards form (vectorized)
    pub fn to_twisted_edward(&self) -> JubjubPointVec {
        let mut ted = JubjubPointVec::new(VBn254Fr::new(), VBn254Fr::new());
        divmod_vec(&mut ted.x, &self.x, &self.y);

        let mut temp = VBn254Fr::new();
        submod_constant(&mut ted.y, &self.x, &VEC_ONE);
        addmod_constant(&mut temp, &self.x, &VEC_ONE);
        ted.y.divmod_vec(&temp);

        ted
    }

    /// Vectorized Twisted Edwards point addition
    pub fn twisted_edward_add(a: &JubjubPointVec, b: &JubjubPointVec) -> JubjubPointVec {
        let mut lambda = VBn254Fr::new();
        mulmod_constant(&mut lambda, &a.x, &VEC_D);
        lambda.mulmod_vec(&a.y);
        lambda.mulmod_vec(&b.x);
        lambda.mulmod_vec(&b.y);

        let mut t1 = VBn254Fr::new();
        let mut t2 = VBn254Fr::new();
        let mut t3 = VBn254Fr::new();

        mulmod_vec(&mut t1, &a.x, &b.y);
        mulmod_vec(&mut t2, &a.y, &b.x);
        addmod_constant(&mut t3, &lambda, &VEC_ONE);

        t1.addmod_vec(&t2);
        let mut result_x = VBn254Fr::new();
        divmod_vec(&mut result_x, &t1, &t3);

        mulmod_vec(&mut t1, &a.y, &b.y);
        mulmod_vec(&mut t2, &a.x, &b.x);
        t2.mulmod_constant(&VEC_A);
        constant_submod(&mut t3, &VEC_ONE, &lambda);

        t1.submod_vec(&t2);
        let mut result_y = VBn254Fr::new();
        divmod_vec(&mut result_y, &t1, &t3);

        JubjubPointVec::new(result_x, result_y)
    }

    /// Vectorized Montgomery point doubling
    pub fn montgomery_double(p: &JubjubPointVec) -> JubjubPointVec {
        let mut result = JubjubPointVec::new(VBn254Fr::new(), VBn254Fr::new());

        let mut lam = VBn254Fr::new();
        mulmod_constant(&mut lam, &p.x, &VEC_THREE);
        lam.mulmod_vec(&p.x);

        let mut t1 = VBn254Fr::new();
        mulmod_constant(&mut t1, &p.x, &VEC_TWO_A);

        lam.addmod_vec(&t1);
        lam.addmod_constant(&VEC_ONE);

        let mut t2 = VBn254Fr::new();
        mulmod_constant(&mut t2, &p.y, &VEC_TWO);

        lam.divmod_vec(&t2);

        let mut t4 = VBn254Fr::new();
        mulmod_vec(&mut result.x, &lam, &lam);
        mulmod_constant(&mut t4, &p.x, &VEC_TWO);
        result.x.submod_vec(&t4);
        result.x.submod_constant(&VEC_MONT_A);

        let mut t5 = VBn254Fr::new();
        submod_vec(&mut t5, &p.x, &result.x);
        mulmod_vec(&mut result.y, &lam, &t5);
        result.y.submod_vec(&p.y);

        result
    }

    /// Vectorized scalar multiplication
    pub fn scalar_mul(&self, x: &VBn254Fr) -> JubjubPointVec {
        let bits = x.bit_decompose();

        let w0 = JubjubPointVec::identity();
        let w1 = self.clone();
        let w2 = JubjubPointVec::twisted_edward_add(self, self);
        let w3 = JubjubPointVec::twisted_edward_add(&w1, &w2);

        let mut acc = JubjubPointVec::mux2(&bits[252], &bits[253], &w0, &w1, &w2, &w3);

        for i in (0..251).step_by(2).rev() {
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);

            acc = JubjubPointVec::twisted_edward_add(
                &acc,
                &JubjubPointVec::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3),
            );
        }

        acc
    }

    /// Vectorized extended scalar multiplication
    pub fn scalar_mul_extend(&self, x1: &VBn254Fr, x2: &VBn254Fr) -> JubjubPointVec {
        let w0 = JubjubPointVec::identity();
        let w1 = self.clone();
        let w2 = JubjubPointVec::twisted_edward_add(self, self);
        let w3 = JubjubPointVec::twisted_edward_add(&w1, &w2);

        // Process x2 first
        let mut bits = x2.bit_decompose();
        let mut acc = JubjubPointVec::mux2(&bits[252], &bits[253], &w0, &w1, &w2, &w3);

        for i in (0..251).step_by(2).rev() {
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);

            acc = JubjubPointVec::twisted_edward_add(
                &acc,
                &JubjubPointVec::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3),
            );
        }

        // Process x1
        bits = x1.bit_decompose();
        for i in (0..253).step_by(2).rev() {
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);
            acc = JubjubPointVec::twisted_edward_add(&acc, &acc);

            acc = JubjubPointVec::twisted_edward_add(
                &acc,
                &JubjubPointVec::mux2(&bits[i], &bits[i + 1], &w0, &w1, &w2, &w3),
            );
        }

        acc
    }
}