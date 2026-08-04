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

//! Affine curve points.

use crate::bn254fr::{land_checked, Bn254Fr};
use crate::ff::{FieldElement, PrimeField};

/// A curve point in affine coordinates.
pub struct Affine<F: PrimeField> {
    pub x: FieldElement<F>,
    pub y: FieldElement<F>,
}

impl<F: PrimeField> Clone for Affine<F> {
    fn clone(&self) -> Self {
        Self {
            x: self.x.clone(),
            y: self.y.clone(),
        }
    }
}

impl<F: PrimeField> Affine<F> {
    pub fn new(x: FieldElement<F>, y: FieldElement<F>) -> Self {
        Self { x, y }
    }

    /// `cond ? a1 : a0`, component-wise.
    ///
    /// Note the polarity: `a1` is chosen when `cond` is 1, matching `bn254fr_mux`. This is the
    /// only branching primitive available on secret data — both arms are always evaluated.
    pub fn select(cond: &Bn254Fr, a0: &Self, a1: &Self) -> Self {
        Self {
            x: FieldElement::mux(cond, &a0.x, &a1.x),
            y: FieldElement::mux(cond, &a0.y, &a1.y),
        }
    }

    /// Circuit boolean: 1 when both coordinates match.
    ///
    /// Not `PartialEq` — the answer is a wire, not a `bool`.
    #[allow(clippy::should_implement_trait)]
    pub fn eq(&self, other: &Self) -> Bn254Fr {
        let eqx = FieldElement::eq(&self.x, &other.x);
        let eqy = FieldElement::eq(&self.y, &other.y);
        let mut out = Bn254Fr::new();
        land_checked(&mut out, &eqx, &eqy);
        out
    }

    /// Forces both coordinates to canonical form.
    ///
    /// The curve code calls this after every point operation; skipping it lets limb widths
    /// grow until they exceed the overflow ceiling.
    pub fn reduce(&self) {
        self.x.reduce();
        self.y.reduce();
    }
}
