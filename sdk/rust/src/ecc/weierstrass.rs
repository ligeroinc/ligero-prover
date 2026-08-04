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

//! Short Weierstrass curves: `y² = x³ + ax + b`.

use super::coordinates::Affine;
use super::curve::CurveForm;
use crate::bn254fr::{land_checked, Bn254Fr};
use crate::ff::{FieldElement, PrimeField};

/// A short Weierstrass curve over the base field `F`.
///
/// The identity is the sentinel `(0, 0)`, which is **not** a curve point but is recognised and
/// preserved by every operation here.
pub struct Weierstrass<F: PrimeField> {
    a: FieldElement<F>,
    b: FieldElement<F>,
    /// Cached identity: rebuilding it per call would materialise a fresh constant on each of
    /// the thousands of point operations in a scalar multiplication.
    inf: Affine<F>,
}

impl<F: PrimeField> Weierstrass<F> {
    pub fn new(a: FieldElement<F>, b: FieldElement<F>) -> Self {
        Self {
            a,
            b,
            inf: Affine::new(FieldElement::zero(), FieldElement::zero()),
        }
    }

    pub fn param_a(&self) -> &FieldElement<F> {
        &self.a
    }

    pub fn param_b(&self) -> &FieldElement<F> {
        &self.b
    }
}

impl<F: PrimeField> CurveForm for Weierstrass<F> {
    type Base = F;

    fn infinity(&self) -> &Affine<F> {
        &self.inf
    }

    fn is_inf(&self, p: &Affine<F>) -> Bn254Fr {
        let xz = FieldElement::eqz(&p.x);
        let yz = FieldElement::eqz(&p.y);
        let mut out = Bn254Fr::new();
        land_checked(&mut out, &xz, &yz);
        out
    }

    /// `y² == x³ + ax + b`
    fn on_curve(&self, p: &Affine<F>) -> Bn254Fr {
        let yy = &p.y * &p.y;
        let xxx = &(&p.x * &p.x) * &p.x;
        let ax = &self.a * &p.x;
        let rhs = &(&xxx + &ax) + &self.b;
        FieldElement::eq(&yy, &rhs)
    }

    /// `-(x, y) = (x, -y)`
    fn negate(&self, p: &Affine<F>) -> Affine<F> {
        Affine::new(p.x.clone(), p.y.negate())
    }

    /// Partial affine addition.
    ///
    /// Handles `p1 = O`, `p2 = O` and `p1 = -p2`, but **not** `p1 == p2` — callers must route
    /// that case to [`CurveForm::double`] themselves. The division uses a substituted dummy
    /// divisor when the real one is zero, so the gadget never divides by zero.
    fn add(&self, p1: &Affine<F>, p2: &Affine<F>) -> Affine<F> {
        let p1_zero = self.is_inf(p1);
        let p2_zero = self.is_inf(p2);

        let x_eq = FieldElement::eq(&p1.x, &p2.x);
        let y_sum = &p1.y + &p2.y;
        let y_neg = FieldElement::eqz(&y_sum);
        let mut p1_add_p2_zero = Bn254Fr::new();
        land_checked(&mut p1_add_p2_zero, &x_eq, &y_neg);

        let u1 = &p2.y - &p1.y;
        let u2 = &p2.x - &p1.x;
        let u2_zero = FieldElement::eqz(&u2);
        let div = FieldElement::mux(&u2_zero, &u2, &u1);
        let lam = &u1 / &div;
        let lam2 = &lam * &lam;
        let t1 = &lam2 - &p1.x;
        let x3 = &t1 - &p2.x;
        let t2 = &p1.x - &x3;
        let t3 = &lam * &t2;
        let y3 = &t3 - &p1.y;

        // The nesting order of these three selects is load-bearing.
        let q0 = Affine::select(&p1_add_p2_zero, &Affine::new(x3, y3), self.infinity());
        let q1 = Affine::select(&p2_zero, &q0, p1);
        Affine::select(&p1_zero, &q1, p2)
    }

    /// Affine doubling, preserving the `(0, 0)` sentinel.
    fn double(&self, p: &Affine<F>) -> Affine<F> {
        let x12 = &p.x * &p.x;
        let u1 = &(&x12 + &x12) + &x12;
        let u2 = &u1 + &self.a;
        let u3 = &p.y + &p.y;

        // Substitute a dummy divisor for the identity so the division stays well defined.
        let eqz = self.is_inf(p);
        let divisor = FieldElement::mux(&eqz, &u3, &u2);
        let lam = &u2 / &divisor;
        let lam2 = &lam * &lam;
        let t1 = &lam2 - &p.x;
        let x3 = &t1 - &p.x;
        let t2 = &p.x - &x3;
        let t3 = &lam * &t2;
        let y3 = &t3 - &p.y;

        // Restore the sentinel when the input was the identity.
        Affine::select(&eqz, &Affine::new(x3, y3), p)
    }
}
