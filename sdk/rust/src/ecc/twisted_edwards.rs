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

//! Twisted Edwards curves with `a = -1`: `-x² + y² = 1 + d·x²y²`.
//!
//! The addition law is complete, so unlike
//! [`Weierstrass`](super::weierstrass::Weierstrass) there is no sentinel identity and no
//! special-casing: `(0, 1)` is a genuine curve point and every input is handled by the same
//! formula.

use super::coordinates::Affine;
use super::curve::CurveForm;
use crate::bn254fr::{land_checked, Bn254Fr};
use crate::ff::{FieldElement, PrimeField};

/// A twisted Edwards curve with `a = -1` over the base field `F`.
pub struct Am1TwistedEdwards<F: PrimeField> {
    d: FieldElement<F>,
    /// Cached constants: rebuilding them inside the formulas would allocate on every point
    /// operation.
    one: FieldElement<F>,
    two: FieldElement<F>,
    inf: Affine<F>,
}

impl<F: PrimeField> Am1TwistedEdwards<F> {
    pub fn new(d: FieldElement<F>) -> Self {
        Self {
            d,
            one: FieldElement::one(),
            two: FieldElement::from_u32(2),
            inf: Affine::new(FieldElement::zero(), FieldElement::one()),
        }
    }

    pub fn param_d(&self) -> &FieldElement<F> {
        &self.d
    }
}

impl<F: PrimeField> CurveForm for Am1TwistedEdwards<F> {
    type Base = F;

    fn infinity(&self) -> &Affine<F> {
        &self.inf
    }

    fn is_inf(&self, p: &Affine<F>) -> Bn254Fr {
        let xz = FieldElement::eqz(&p.x);
        let yo = FieldElement::eq(&p.y, &self.one);
        let mut out = Bn254Fr::new();
        land_checked(&mut out, &xz, &yo);
        out
    }

    /// `y² - x² == 1 + d·x²y²`
    fn on_curve(&self, p: &Affine<F>) -> Bn254Fr {
        let xx = &p.x * &p.x;
        let yy = &p.y * &p.y;
        let xxyy = &xx * &yy;
        let lhs = &yy - &xx;
        let rhs = &self.one + &(&self.d * &xxyy);
        FieldElement::eq(&lhs, &rhs)
    }

    /// `-(x, y) = (-x, y)`
    fn negate(&self, p: &Affine<F>) -> Affine<F> {
        Affine::new(p.x.negate(), p.y.clone())
    }

    /// Complete affine addition — no exceptional cases.
    fn add(&self, p1: &Affine<F>, p2: &Affine<F>) -> Affine<F> {
        let x1y2 = &p1.x * &p2.y;
        let x2y1 = &p2.x * &p1.y;
        let y1y2 = &p1.y * &p2.y;
        let x1x2 = &p1.x * &p2.x;
        let x1x2y1y2 = &x1x2 * &y1y2;
        let dxy = &self.d * &x1x2y1y2;

        let t1 = &x1y2 + &x2y1;
        let t2 = &self.one + &dxy;
        let x3 = &t1 / &t2;

        let t3 = &y1y2 + &x1x2;
        let t4 = &self.one - &dxy;
        let y3 = &t3 / &t4;

        Affine::new(x3, y3)
    }

    fn double(&self, p: &Affine<F>) -> Affine<F> {
        let xx = &p.x * &p.x;
        let yy = &p.y * &p.y;
        let xy = &p.x * &p.y;

        let t1 = &xy + &xy;
        let t2 = &yy - &xx;
        let x3 = &t1 / &t2;

        let t3 = &xx + &yy;
        let t4 = &self.two - &t2;
        let y3 = &t3 / &t4;

        Affine::new(x3, y3)
    }
}
