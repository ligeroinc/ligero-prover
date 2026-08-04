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

//! Curve abstractions.

use super::coordinates::Affine;
use super::host::{self, EccCurveType};
use super::utils::point_select_2d;
use crate::api;
use crate::bn254fr::{assert_equal_u32, Bn254Fr};
use crate::bn254fr_bigint::Bn254FrBigint;
use crate::ff::{FieldElement, PrimeField};

/// The point operations that depend on the curve's *shape* rather than its parameters.
///
/// Implemented once per curve family: [`Weierstrass`](super::weierstrass::Weierstrass) and
/// [`Am1TwistedEdwards`](super::twisted_edwards::Am1TwistedEdwards).
pub trait CurveForm {
    type Base: PrimeField;

    /// The identity element.
    fn infinity(&self) -> &Affine<Self::Base>;
    /// Circuit boolean: 1 when `p` is the identity.
    fn is_inf(&self, p: &Affine<Self::Base>) -> Bn254Fr;
    /// Circuit boolean: 1 when `p` satisfies the curve equation.
    fn on_curve(&self, p: &Affine<Self::Base>) -> Bn254Fr;
    fn negate(&self, p: &Affine<Self::Base>) -> Affine<Self::Base>;
    fn double(&self, p: &Affine<Self::Base>) -> Affine<Self::Base>;
    fn add(&self, p1: &Affine<Self::Base>, p2: &Affine<Self::Base>) -> Affine<Self::Base>;
}

/// A curve in affine coordinates over a pair of prime fields.
pub trait AffineCurve: Sized {
    type Base: PrimeField;
    type Scalar: PrimeField;
    type Form: CurveForm<Base = Self::Base>;

    /// Selector for the host oracles.
    const CURVE_TYPE: EccCurveType;
    /// Group order, big-endian.
    const ORDER_BE: &'static [u8; 32];
    /// Base field modulus, big-endian.
    const BASE_FIELD_BE: &'static [u8; 32];

    const BASE_FIELD_BYTES: usize = Self::Base::NUM_ROUNDED_BITS / 8;
    const SCALAR_FIELD_BYTES: usize = Self::Scalar::NUM_ROUNDED_BITS / 8;

    fn form(&self) -> &Self::Form;
    fn generator(&self) -> &Affine<Self::Base>;

    /// `[k] G`, using the curve's precomputed generator table.
    fn scalar_mul_generator(&self, k: &FieldElement<Self::Scalar>) -> Affine<Self::Base>;

    // ---- forwarders, so call sites read naturally ----

    fn infinity(&self) -> &Affine<Self::Base> {
        self.form().infinity()
    }
    fn is_inf(&self, p: &Affine<Self::Base>) -> Bn254Fr {
        self.form().is_inf(p)
    }
    fn on_curve(&self, p: &Affine<Self::Base>) -> Bn254Fr {
        self.form().on_curve(p)
    }
    fn point_negate(&self, p: &Affine<Self::Base>) -> Affine<Self::Base> {
        self.form().negate(p)
    }
    fn point_double(&self, p: &Affine<Self::Base>) -> Affine<Self::Base> {
        self.form().double(p)
    }
    fn point_add(&self, p1: &Affine<Self::Base>, p2: &Affine<Self::Base>) -> Affine<Self::Base> {
        self.form().add(p1, p2)
    }

    /// Constrains `p` to lie on the curve.
    fn assert_on_curve(&self, p: &Affine<Self::Base>) {
        assert_equal_u32(&self.on_curve(p), 1);
    }

    /// `[k] point`, proved with a two-scalar multi-scalar multiplication.
    ///
    /// ## How it works
    ///
    /// Proving `[k]P = Q` directly would need 256 point doublings. Instead the host supplies
    /// both `Q = [k]P` and a rational reconstruction `k ≡ x/z (mod n)` with `|x|, |z| < √n`,
    /// and the circuit proves the equivalent `[x]P − [z]Q = O`. Because `x` and `z` are only
    /// 128 bits and share one doubling chain, that halves the doublings.
    ///
    /// Sign handling: from `x_signed ≡ z_signed · k (mod n)` we get
    /// `x_signed·point − z_signed·result = O`, so folding the signs into `P := sign(x)·point`
    /// and `Q := −sign(z)·result` leaves `|x|·P + |z|·Q = O` for the unsigned bit loop. That
    /// is why the two `select` calls below negate on opposite conditions — it is deliberate,
    /// not a typo.
    ///
    /// `k = 0` is not supported: the `x != 0` constraint together with `x ≡ 0 (mod n)` and
    /// `0 < x < √n` is unsatisfiable.
    fn scalar_mul(
        &self,
        k: &FieldElement<Self::Scalar>,
        point: &Affine<Self::Base>,
    ) -> Affine<Self::Base> {
        const WINDOW_BITS: usize = 2;

        let nb = Self::BASE_FIELD_BYTES;
        let ns = Self::SCALAR_FIELD_BYTES;

        // 1. Host oracle: result = [k] point.
        let mut point_bytes = vec![0u8; 2 * nb];
        point.x.export_bytes_little(&mut point_bytes[..nb]);
        point.y.export_bytes_little(&mut point_bytes[nb..2 * nb]);

        let mut k_bytes = vec![0u8; ns];
        k.export_bytes_little(&mut k_bytes);
        // Test-only seams. No-ops unless `--features fault-injection`, and absent from the
        // build entirely without it. They exist because no *input* can reach the assertions
        // below: the honest oracle always answers correctly. See `crate::ecc::fault`.
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_scalar(&mut k_bytes);

        let mut out_bytes = vec![0u8; 2 * nb];
        host::scalar_mul(Self::CURVE_TYPE, &mut out_bytes, &point_bytes, &k_bytes);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_point(&mut out_bytes);

        let mut rx = Bn254FrBigint::new();
        let mut ry = Bn254FrBigint::new();
        rx.set_bytes_little(&out_bytes[..nb]);
        ry.set_bytes_little(&out_bytes[nb..2 * nb]);
        let result = Affine::new(
            FieldElement::from_bigint(rx, false),
            FieldElement::from_bigint(ry, false),
        );

        // 2. Host oracle: k ≡ x/z (mod n) with |x|, |z| < √n.
        #[allow(unused_mut)]
        let (mut x_abs, mut x_positive, z_abs, z_positive) =
            host::scalar_decompose(Self::CURVE_TYPE, &k_bytes);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_decomposition(&mut x_abs, &mut x_positive);

        // Importing only half the field width is what bounds |x|, |z| < 2^128. There is no
        // separate range check — this *is* the bound.
        let half = nb / 2;
        let mut x_storage = Bn254FrBigint::new();
        let mut z_storage = Bn254FrBigint::new();
        x_storage.set_bytes_little(&x_abs[..half]);
        z_storage.set_bytes_little(&z_abs[..half]);

        // 3. Booleanity of the sign flags, in the integer domain.
        api::assert_one(i32::from(x_positive * x_positive == x_positive));
        api::assert_one(i32::from(z_positive * z_positive == z_positive));

        // 4. |x| and |z| must be non-zero.
        assert_equal_u32(&x_storage.eqz(), 0);
        assert_equal_u32(&z_storage.eqz(), 0);

        // 5. Bind the witnesses: x_signed == z_signed * k (mod n).
        let x = FieldElement::<Self::Scalar>::from_bigint(x_storage, false);
        let z = FieldElement::<Self::Scalar>::from_bigint(z_storage, false);
        let negx = x.negate();
        let negz = z.negate();
        let xp = Bn254Fr::from_u32(x_positive as u32);
        let zp = Bn254Fr::from_u32(z_positive as u32);
        let x_signed = FieldElement::mux(&xp, &negx, &x);
        let z_signed = FieldElement::mux(&zp, &negz, &z);
        let zk = &z_signed * k;
        let x_eq_zk = FieldElement::eq(&x_signed, &zk);
        assert_equal_u32(&x_eq_zk, 1);

        // 6. Fold the signs into the two MSM bases.
        let p = Affine::select(&xp, &self.point_negate(point), point);
        let q = Affine::select(&zp, &result, &self.point_negate(&result));

        // 7. 4x4 precompute table: precomp[row*4 + col] = row*Q + col*P.
        let mut precomp: Vec<Affine<Self::Base>> =
            (0..16).map(|_| self.infinity().clone()).collect();
        precomp[1] = p.clone();
        precomp[2] = self.point_double(&p);
        precomp[3] = self.point_add(&precomp[2], &p);
        precomp[4] = q.clone();
        precomp[8] = self.point_double(&q);
        precomp[12] = self.point_add(&precomp[8], &q);

        for row in 1..4 {
            for col in 1..4 {
                let idx = row * 4 + col;
                let prev = idx - 4;
                // precomp[idx] = precomp[prev] + Q. `point_add` deliberately does not handle
                // p1 == p2, so the one case where the addend coincides with Q is routed to
                // `double` instead. Recall select(cond, a0, a1) picks a1 when cond is 1, so
                // this reads "if prev == Q then double(Q) else prev + Q".
                let is_q = precomp[prev].eq(&q);
                let added = self.point_add(&precomp[prev], &q);
                let doubled = self.point_double(&q);
                precomp[idx] = Affine::select(&is_q, &added, &doubled);
            }
        }

        // Index 0 is the identity and is deliberately left alone.
        for entry in precomp.iter().skip(1) {
            entry.reduce();
        }

        // 8. Horner loop over the low half of the scalar.
        let window_count = (Self::Scalar::NUM_ROUNDED_BITS / 2) / WINDOW_BITS;
        let x_bits = x.to_bits();
        let z_bits = z.to_bits();

        let mut off = (window_count - 1) * WINDOW_BITS;
        let mut acc = point_select_2d(WINDOW_BITS, &x_bits[off..], &z_bits[off..], &precomp);

        for i in (0..window_count - 1).rev() {
            for _ in 0..WINDOW_BITS {
                acc = self.point_double(&acc);
                acc.reduce();
            }
            off = i * WINDOW_BITS;
            let t = point_select_2d(WINDOW_BITS, &x_bits[off..], &z_bits[off..], &precomp);
            // Argument order matters: point_add is a mux chain whose evaluation differs by
            // operand.
            acc = self.point_add(&t, &acc);
            acc.reduce();
        }

        // 9. [x]P + [z]Q must be the identity, which is what proves result == [k]point.
        assert_equal_u32(&self.is_inf(&acc), 1);

        result
    }
}
