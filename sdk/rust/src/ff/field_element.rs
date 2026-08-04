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

//! The prime field value type.

use core::ops::{Add, Div, Mul, Neg, Sub};

use super::{PrimeField, PrimeFieldStorage};
use crate::bn254fr::Bn254Fr;
use crate::bn254fr_bigint::Bn254FrBigint;
use crate::uint256::Uint256;

/// An element of the prime field `F`.
///
/// Every operation emits constraints, so this is not a cheap value type — prefer the
/// out-parameter forms ([`FieldElement::add`] and friends) in hot loops, and the operators
/// where readability matters.
///
/// **There is deliberately no `PartialEq`.** Equality is a circuit value; use
/// [`FieldElement::eq`], which returns a [`Bn254Fr`] holding 0 or 1.
#[repr(transparent)]
pub struct FieldElement<F: PrimeField>(PrimeFieldStorage<F>);

impl<F: PrimeField> Clone for FieldElement<F> {
    /// Emits an equality constraint per limb.
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<F: PrimeField> Default for FieldElement<F> {
    fn default() -> Self {
        Self::zero()
    }
}

impl<F: PrimeField> FieldElement<F> {
    /// Bits produced by [`FieldElement::to_bits`].
    pub const NUM_ROUNDED_BITS: usize = F::NUM_ROUNDED_BITS;
    /// Canonical byte width.
    pub const NUM_BYTES: usize = F::NUM_BYTES;

    // ---------------------------------------------------------------- construction

    pub fn zero() -> Self {
        Self(PrimeFieldStorage::new())
    }

    pub fn one() -> Self {
        Self(PrimeFieldStorage::from_u64(1))
    }

    pub fn from_u32(v: u32) -> Self {
        Self(PrimeFieldStorage::from_u64(v as u64))
    }

    pub fn from_u64(v: u64) -> Self {
        Self(PrimeFieldStorage::from_u64(v))
    }

    /// From a decimal or `0x`-prefixed hex string.
    pub fn from_str(s: &str) -> Self {
        Self(PrimeFieldStorage::from_str(s))
    }

    /// From a [`Uint256`].
    pub fn from_uint256(x: &Uint256) -> Self {
        Self(PrimeFieldStorage::from_uint256(x))
    }

    /// From raw big-integer limbs, with an explicit reduction claim.
    pub fn from_bigint(value: Bn254FrBigint, reduced: bool) -> Self {
        Self(PrimeFieldStorage::from_bigint(value, reduced))
    }

    /// Reinterprets an element of another field in this one, reducing modulo this modulus.
    ///
    /// ECDSA uses this to lift a curve point's x-coordinate from the base field into the
    /// scalar field.
    pub fn from_other_field<F2: PrimeField>(other: &FieldElement<F2>) -> Self {
        Self(PrimeFieldStorage::from_other_field(other.data()))
    }

    // ---------------------------------------------------------------- accessors

    pub fn data(&self) -> &PrimeFieldStorage<F> {
        &self.0
    }

    pub fn data_mut(&mut self) -> &mut PrimeFieldStorage<F> {
        &mut self.0
    }

    /// Exports to a [`Uint256`], reducing first.
    pub fn to_uint256(&self) -> Uint256 {
        self.0.to_uint256()
    }

    pub fn set_zero(&mut self) {
        self.0.set_zero()
    }

    pub fn set_one(&mut self) {
        self.0.set_one()
    }

    /// Forces reduction to canonical form.
    ///
    /// The curve code calls this after every point operation to keep limb widths bounded.
    pub fn reduce(&self) {
        self.0.reduce()
    }

    // ---------------------------------------------------------------- arithmetic

    pub fn add(out: &mut Self, x: &Self, y: &Self) {
        PrimeFieldStorage::add(&mut out.0, &x.0, &y.0)
    }

    pub fn sub(out: &mut Self, x: &Self, y: &Self) {
        PrimeFieldStorage::sub(&mut out.0, &x.0, &y.0)
    }

    pub fn mul(out: &mut Self, x: &Self, y: &Self) {
        PrimeFieldStorage::mul(&mut out.0, &x.0, &y.0)
    }

    pub fn div(out: &mut Self, x: &Self, y: &Self) {
        PrimeFieldStorage::div(&mut out.0, &x.0, &y.0)
    }

    pub fn neg_into(out: &mut Self, x: &Self) {
        PrimeFieldStorage::neg(&mut out.0, &x.0)
    }

    pub fn inv_into(out: &mut Self, x: &Self) {
        PrimeFieldStorage::inv(&mut out.0, &x.0)
    }

    pub fn sqr(out: &mut Self, x: &Self) {
        PrimeFieldStorage::sqr(&mut out.0, &x.0)
    }

    /// `out = base^exp`. The exponent is public and must not depend on secret data.
    pub fn powm_ui(out: &mut Self, base: &Self, exp: u32) {
        PrimeFieldStorage::powm_ui(&mut out.0, &base.0, exp)
    }

    /// `-x`, with `-0 == 0`.
    pub fn negate(&self) -> Self {
        let mut out = Self::zero();
        Self::neg_into(&mut out, self);
        out
    }

    /// `x^-1 (mod p)`.
    pub fn inv(&self) -> Self {
        let mut out = Self::zero();
        Self::inv_into(&mut out, self);
        out
    }

    // ---------------------------------------------------------------- selection

    /// `cond ? y : x` — note the polarity, matching `bn254fr_mux`.
    ///
    /// This is the only way to branch on a circuit value: both arms are always evaluated.
    pub fn mux(cond: &Bn254Fr, x: &Self, y: &Self) -> Self {
        let mut out = Self::zero();
        PrimeFieldStorage::mux(&mut out.0, cond, &x.0, &y.0);
        out
    }

    /// Circuit boolean: 1 when `a == b`.
    #[allow(clippy::should_implement_trait)]
    pub fn eq(a: &Self, b: &Self) -> Bn254Fr {
        PrimeFieldStorage::eq(&a.0, &b.0)
    }

    /// Circuit boolean: 1 when `a` is zero.
    pub fn eqz(a: &Self) -> Bn254Fr {
        a.0.eqz()
    }

    /// Constrains two elements to be equal.
    pub fn assert_equal(a: &Self, b: &Self) {
        PrimeFieldStorage::assert_equal(&a.0, &b.0)
    }

    // ---------------------------------------------------------------- import/export

    /// Imports from 32-bit limbs, least-significant first.
    pub fn import_limbs(&mut self, limbs: &[u32]) -> usize {
        self.0.import_u32(limbs)
    }

    /// Exports to 32-bit limbs, least-significant first.
    pub fn export_limbs(&self, limbs: &mut [u32]) -> usize {
        self.0.export_u32(limbs)
    }

    pub fn import_bytes_little(&mut self, bytes: &[u8]) {
        self.0.import_bytes_little(bytes);
    }

    pub fn import_bytes_big(&mut self, bytes: &[u8]) {
        self.0.import_bytes_big(bytes);
    }

    /// Imports in the given order: `-1` little-endian, `1` big-endian.
    pub fn import_bytes(&mut self, bytes: &[u8], order: i32) {
        if order == crate::bn254fr::ORDER_LITTLE {
            self.import_bytes_little(bytes)
        } else {
            self.import_bytes_big(bytes)
        }
    }

    pub fn export_bytes_little(&self, bytes: &mut [u8]) -> usize {
        self.0.export_bytes_little(bytes)
    }

    pub fn export_bytes_big(&self, bytes: &mut [u8]) -> usize {
        self.0.export_bytes_big(bytes)
    }

    /// Exports in the given order: `-1` little-endian, `1` big-endian.
    pub fn export_bytes(&self, bytes: &mut [u8], order: i32) -> usize {
        if order == crate::bn254fr::ORDER_LITTLE {
            self.export_bytes_little(bytes)
        } else {
            self.export_bytes_big(bytes)
        }
    }

    /// Decomposes into [`NUM_ROUNDED_BITS`](Self::NUM_ROUNDED_BITS) bits, LSB first.
    pub fn to_bits(&self) -> Vec<Bn254Fr> {
        self.0.to_bits()
    }

    pub fn print(&self) {
        self.0.print()
    }
}

// Operators are implemented on references: the type is not `Copy`, and every operation emits
// constraints, so accidental by-value use would be expensive and silent.

impl<F: PrimeField> Add for &FieldElement<F> {
    type Output = FieldElement<F>;
    fn add(self, rhs: Self) -> FieldElement<F> {
        let mut out = FieldElement::zero();
        FieldElement::add(&mut out, self, rhs);
        out
    }
}

impl<F: PrimeField> Sub for &FieldElement<F> {
    type Output = FieldElement<F>;
    fn sub(self, rhs: Self) -> FieldElement<F> {
        let mut out = FieldElement::zero();
        FieldElement::sub(&mut out, self, rhs);
        out
    }
}

impl<F: PrimeField> Mul for &FieldElement<F> {
    type Output = FieldElement<F>;
    fn mul(self, rhs: Self) -> FieldElement<F> {
        let mut out = FieldElement::zero();
        FieldElement::mul(&mut out, self, rhs);
        out
    }
}

impl<F: PrimeField> Div for &FieldElement<F> {
    type Output = FieldElement<F>;
    fn div(self, rhs: Self) -> FieldElement<F> {
        let mut out = FieldElement::zero();
        FieldElement::div(&mut out, self, rhs);
        out
    }
}

impl<F: PrimeField> Neg for &FieldElement<F> {
    type Output = FieldElement<F>;
    fn neg(self) -> FieldElement<F> {
        self.negate()
    }
}
