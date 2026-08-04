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

//! Storage and arithmetic backing [`FieldElement`](super::FieldElement).

use core::cell::RefCell;
use core::marker::PhantomData;

use super::PrimeField;
use crate::bn254fr::Bn254Fr;
use crate::bn254fr_bigint::{
    mul_checked_no_carry_bits, Bn254FrBigint, BASE_BITS_COUNT, MAX_BITS_COUNT,
};
use crate::uint256::{Uint256, UINT256_NLIMBS};

/// Ceiling on limb width before an operand must be normalised.
const N_MAX_BITS: u32 = MAX_BITS_COUNT;

/// Bits per limb in proper representation.
const N_BITS_BASE: u32 = BASE_BITS_COUNT;

struct Inner {
    value: Bn254FrBigint,
    is_reduced: bool,
}

/// A field element's limbs plus its reduction state.
///
/// ## Interior mutability
///
/// Reduction is cache normalisation, not a semantic change, so it happens through `&self` —
/// The `RefCell` is what makes
/// `impl Mul for &FieldElement` possible; threading `&mut` upward instead would force every
/// operator to take unique references and destroy the ergonomics.
///
/// **Borrow discipline:** never hold a `Ref`/`RefMut` across a call that can reduce. Read the
/// widths you need, drop the guard, reduce, then re-borrow. Because `&mut Self` and `&Self`
/// cannot alias, the out-param forms can never self-alias, so the only real panic risk is a
/// reduction under an outstanding guard.
pub struct PrimeFieldStorage<F: PrimeField> {
    inner: RefCell<Inner>,
    _f: PhantomData<F>,
}

impl<F: PrimeField> Clone for PrimeFieldStorage<F> {
    /// Emits an equality constraint per limb.
    fn clone(&self) -> Self {
        let g = self.inner.borrow();
        Self::from_parts(g.value.clone(), g.is_reduced)
    }
}

impl<F: PrimeField> Default for PrimeFieldStorage<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeField> PrimeFieldStorage<F> {
    fn from_parts(value: Bn254FrBigint, is_reduced: bool) -> Self {
        Self {
            inner: RefCell::new(Inner { value, is_reduced }),
            _f: PhantomData,
        }
    }

    // ---------------------------------------------------------------- construction

    /// Zero.
    pub fn new() -> Self {
        Self::from_parts(Bn254FrBigint::with_limbs(UINT256_NLIMBS), true)
    }

    /// From a `u64`. Always smaller than the modulus, so already reduced.
    pub fn from_u64(v: u64) -> Self {
        Self::from_parts(Bn254FrBigint::from_u64(UINT256_NLIMBS, v), true)
    }

    /// From a big integer, with an explicit reduction claim.
    pub fn from_bigint(value: Bn254FrBigint, reduced: bool) -> Self {
        Self::from_parts(value, reduced)
    }

    /// From a decimal or `0x`-prefixed hex string.
    pub fn from_str(s: &str) -> Self {
        Self::from_uint256(&Uint256::from_str(s, 0))
    }

    /// From a [`Uint256`].
    pub fn from_uint256(x: &Uint256) -> Self {
        let mut res = Self::new();
        res.set_uint256(x);
        res
    }

    /// Reinterprets another field's limbs as this field's, reducing modulo this modulus.
    ///
    /// ECDSA needs this to lift the x-coordinate of a curve point out of the base field into
    /// the scalar field (SEC1 §4.1.4's "x mod n").
    pub fn from_other_field<F2: PrimeField>(other: &PrimeFieldStorage<F2>) -> Self {
        Self::from_uint256(&other.to_uint256())
    }

    // ---------------------------------------------------------------- conversion

    /// Reduces, then exports to a [`Uint256`].
    pub fn to_uint256(&self) -> Uint256 {
        self.reduce();

        let g = self.inner.borrow();
        assert_eq!(
            g.value.limbs_count(),
            UINT256_NLIMBS,
            "invalid limb count after reduce"
        );

        let mut words = [
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
        ];
        for i in 0..UINT256_NLIMBS {
            crate::bn254fr::raw::copy(words[i].handle_mut(), &g.value.limbs()[i]);
        }
        drop(g);

        let mut res = Uint256::new();
        res.set_words_checked(&words);
        res
    }

    /// Sets the value from a [`Uint256`]. The result is not assumed reduced.
    pub fn set_uint256(&mut self, x: &Uint256) {
        let mut g = self.inner.borrow_mut();
        g.value.set(x.limbs_all(), N_BITS_BASE, true);
        g.is_reduced = false;
    }

    // ---------------------------------------------------------------- state

    /// Number of limbs currently held.
    pub fn size(&self) -> usize {
        self.inner.borrow().value.limbs_count()
    }

    /// Current per-limb width bound.
    pub fn bits_count(&self) -> u32 {
        self.inner.borrow().value.bits_count()
    }

    /// Whether the limbs are currently unsigned.
    pub fn is_unsigned_flag(&self) -> bool {
        self.inner.borrow().value.is_unsigned()
    }

    /// Whether the value is known to be fully reduced.
    pub fn is_reduced(&self) -> bool {
        self.inner.borrow().is_reduced
    }

    /// Reduces modulo the field modulus, if not already reduced.
    ///
    /// Afterwards the value is in proper representation with exactly [`UINT256_NLIMBS`] limbs.
    pub fn reduce(&self) {
        if self.inner.borrow().is_reduced {
            return;
        }

        // Compute with no borrow outstanding: rem() can allocate and constrain freely.
        let res = {
            let g = self.inner.borrow();
            Bn254FrBigint::rem(&g.value, F::modulus())
        };

        let mut g = self.inner.borrow_mut();
        g.value = res;
        g.is_reduced = true;
    }

    /// Prints the value.
    pub fn dump(&self) {
        self.inner.borrow().value.dump();
    }

    // ---------------------------------------------------------------- arithmetic

    /// Reduces whichever operands are needed to keep the projected result under the width
    /// ceiling.
    ///
    /// The order matters: the wider operand is reduced first, and only if that is still not
    /// enough is the other one reduced too. Changing the order changes the constraint
    /// sequence.
    fn convert_args_to_proper_if_required<Calc>(calc: Calc, x: &Self, y: &Self)
    where
        Calc: Fn(&Self, &Self) -> u32,
    {
        if calc(x, y) > N_MAX_BITS {
            if x.bits_count() > y.bits_count() {
                x.reduce();
                if calc(x, y) > N_MAX_BITS {
                    y.reduce();
                }
            } else {
                y.reduce();
                if calc(x, y) > N_MAX_BITS {
                    x.reduce();
                }
            }
        }
    }

    /// `out = x + y`
    pub fn add(out: &mut Self, x: &Self, y: &Self) {
        Self::convert_args_to_proper_if_required(
            |x, y| x.bits_count().max(y.bits_count()) + 1,
            x,
            y,
        );

        let res = {
            let (xg, yg) = (x.inner.borrow(), y.inner.borrow());
            Bn254FrBigint::add_no_carry(&xg.value, &yg.value)
        };

        let mut og = out.inner.borrow_mut();
        og.value = res;
        og.is_reduced = false;
    }

    /// `out = x - y`
    ///
    /// Adds a multiple of the modulus to `x` first, so the carry-free subtraction never has to
    /// represent a negative intermediate.
    pub fn sub(out: &mut Self, x: &Self, y: &Self) {
        Self::convert_args_to_proper_if_required(
            |x, y| (x.bits_count() + 1).max(y.bits_count()) + 1,
            x,
            y,
        );

        let res = {
            let yg = y.inner.borrow();
            let mult_bits = if yg.value.is_unsigned() {
                yg.value.bits_count()
            } else {
                yg.value.bits_count() - 1
            };
            let mult = calc_overflow_multiplier(yg.value.limbs_count(), mult_bits, F::modulus());

            let xg = x.inner.borrow();
            let x_plus_mult = Bn254FrBigint::add_no_carry(&xg.value, &mult);
            Bn254FrBigint::sub_no_carry(&x_plus_mult, &yg.value)
        };

        let mut og = out.inner.borrow_mut();
        og.value = res;
        og.is_reduced = false;
    }

    /// `out = x * y`
    pub fn mul(out: &mut Self, x: &Self, y: &Self) {
        Self::convert_args_to_proper_if_required(
            |x, y| {
                let (xg, yg) = (x.inner.borrow(), y.inner.borrow());
                Bn254FrBigint::mul_no_carry_res_bits_count(&xg.value, &yg.value)
            },
            x,
            y,
        );

        let res = {
            let (xg, yg) = (x.inner.borrow(), y.inner.borrow());
            Bn254FrBigint::mul_no_carry(&xg.value, &yg.value)
        };

        let mut og = out.inner.borrow_mut();
        og.value = res;
        og.is_reduced = false;
    }

    /// `out = x^-1 (mod p)`
    pub fn inv(out: &mut Self, x: &Self) {
        let res = {
            let xg = x.inner.borrow();
            Bn254FrBigint::invmod(&xg.value, F::modulus())
        };

        let mut og = out.inner.borrow_mut();
        og.value = res;
        og.is_reduced = true;
    }

    /// `out = x / y (mod p)`
    ///
    /// Compute-then-prove: the quotient is obtained from unconstrained oracles, and soundness
    /// comes from the final `out * y === x (mod p)` check. Skipping that check would leave the
    /// result entirely unconstrained.
    pub fn div(out: &mut Self, x: &Self, y: &Self) {
        Self::convert_args_to_proper_if_required(
            |x, y| {
                let yg = y.inner.borrow();
                let mul_res_bits = mul_checked_no_carry_bits(
                    yg.value.limbs_count(),
                    yg.value.bits_count(),
                    UINT256_NLIMBS,
                    N_BITS_BASE,
                );
                drop(yg);
                assert_equal_mod_bits(x.bits_count(), mul_res_bits)
            },
            x,
            y,
        );

        let (res, x_value_snapshot_ok) = {
            let (xg, yg) = (x.inner.borrow(), y.inner.borrow());

            // y^-1 mod p, unconstrained
            let y_inv = Bn254FrBigint::invmod_unchecked(&yg.value, F::modulus());
            // x in proper form, unconstrained
            let x_proper = xg.value.to_proper_unchecked();
            // x * y^-1, unconstrained
            let x_mul_y_inv = Bn254FrBigint::mul_unchecked(&x_proper, &y_inv);
            // reduced, unconstrained
            (
                Bn254FrBigint::rem_unchecked(&x_mul_y_inv, F::modulus()),
                true,
            )
        };
        debug_assert!(x_value_snapshot_ok);

        // Now prove it: x2 = out * y with constraints, then x2 === x (mod p).
        let x2 = {
            let yg = y.inner.borrow();
            Bn254FrBigint::mul_no_carry(&res, &yg.value)
        };
        {
            let xg = x.inner.borrow();
            assert_equal_mod(&xg.value, &x2, F::modulus());
        }

        let mut og = out.inner.borrow_mut();
        og.value = res;
        og.is_reduced = true;
    }

    /// `out = -x`, with `-0 == 0`.
    pub fn neg(out: &mut Self, x: &Self) {
        let eqz_res = x.eqz();
        let sub_res = Self::sub_from_modulus(x);
        // mux(cond, a0, a1) selects a1 when cond is 1, so a zero input maps back to itself.
        Self::mux(out, &eqz_res, &sub_res, x);
    }

    /// `p - x`, matching the gate sequence `sub(_, modulus, x)` would produce.
    ///
    /// The modulus is always proper, so it never needs reducing: exceeding the ceiling would
    /// require `x.bits_count() >= 250`, and in that case the `else` branch reduces `x` first.
    fn sub_from_modulus(x: &Self) -> Self {
        if (N_BITS_BASE + 1).max(x.bits_count()) + 1 > N_MAX_BITS {
            x.reduce();
        }

        let xg = x.inner.borrow();
        let mult_bits = if xg.value.is_unsigned() {
            xg.value.bits_count()
        } else {
            xg.value.bits_count() - 1
        };
        let mult = calc_overflow_multiplier(xg.value.limbs_count(), mult_bits, F::modulus());
        let m_plus_mult = Bn254FrBigint::add_no_carry(F::modulus(), &mult);
        let res = Bn254FrBigint::sub_no_carry(&m_plus_mult, &xg.value);
        drop(xg);

        Self::from_parts(res, false)
    }

    /// `out = x * x`
    pub fn sqr(out: &mut Self, x: &Self) {
        Self::mul(out, x, x);
    }

    /// `out = base^exp`, square-and-multiply over a public exponent.
    ///
    /// Not constant time — it branches on the bits of `exp`, which must therefore be public.
    pub fn powm_ui(out: &mut Self, base: &Self, exp: u32) {
        let mut res = Self::from_u64(1);
        let mut cur_pow = base.clone();
        let mut e = exp;

        while e != 0 {
            if e & 1 != 0 {
                let mut tmp = Self::new();
                Self::mul(&mut tmp, &res, &cur_pow);
                res = tmp;
            }
            e >>= 1;
            let mut tmp2 = Self::new();
            Self::mul(&mut tmp2, &cur_pow, &cur_pow);
            cur_pow = tmp2;
        }

        let src = res.inner.into_inner();
        let mut og = out.inner.borrow_mut();
        og.value = src.value;
        og.is_reduced = src.is_reduced;
    }

    /// `out = cond ? y : x`
    ///
    /// Note the polarity: the **second** value is selected when `cond` is 1, matching
    /// `bn254fr_mux`.
    pub fn mux(out: &mut Self, cond: &Bn254Fr, x: &Self, y: &Self) {
        let (xg, yg) = (x.inner.borrow(), y.inner.borrow());

        let x_size = xg.value.limbs_count();
        let y_size = yg.value.limbs_count();
        let common = x_size.min(y_size);

        let mut value = Bn254FrBigint::with_limbs(x_size.max(y_size));
        let zero = Bn254Fr::new();

        for i in 0..common {
            crate::bn254fr::raw::mux(
                &mut value.limbs_mut()[i],
                cond.handle(),
                &xg.value.limbs()[i],
                &yg.value.limbs()[i],
            );
        }
        for i in common..y_size {
            crate::bn254fr::raw::mux(
                &mut value.limbs_mut()[i],
                cond.handle(),
                zero.handle(),
                &yg.value.limbs()[i],
            );
        }
        for i in common..x_size {
            crate::bn254fr::raw::mux(
                &mut value.limbs_mut()[i],
                cond.handle(),
                &xg.value.limbs()[i],
                zero.handle(),
            );
        }

        let is_unsigned = xg.value.is_unsigned() && yg.value.is_unsigned();
        value.set_unsigned(is_unsigned);

        if is_unsigned {
            value.set_bits_count(xg.value.bits_count().max(yg.value.bits_count()));
        } else {
            // A signed limb needs one more bit than an unsigned one of the same magnitude.
            let x_bits = xg.value.bits_count() + u32::from(xg.value.is_unsigned());
            let y_bits = yg.value.bits_count() + u32::from(yg.value.is_unsigned());
            value.set_bits_count(x_bits.max(y_bits));
        }

        let is_reduced = xg.is_reduced && yg.is_reduced;
        drop(xg);
        drop(yg);

        let mut og = out.inner.borrow_mut();
        og.value = value;
        og.is_reduced = is_reduced;
    }

    /// Circuit boolean: 1 when `x == y`. Reduces both operands first.
    pub fn eq(x: &Self, y: &Self) -> Bn254Fr {
        x.reduce();
        y.reduce();
        let (xg, yg) = (x.inner.borrow(), y.inner.borrow());
        Bn254FrBigint::eq(&xg.value, &yg.value)
    }

    /// Circuit boolean: 1 when this value is zero. Reduces first.
    pub fn eqz(&self) -> Bn254Fr {
        self.reduce();
        self.inner.borrow().value.eqz()
    }

    /// Sets this value to zero.
    ///
    /// The C++ `set_zero`/`set_one` call a `storage.set_u32()` that does not exist; they
    /// compile only because nothing instantiates them. Implemented properly here.
    pub fn set_zero(&mut self) {
        *self = Self::from_u64(0);
    }

    /// Sets this value to one. See [`PrimeFieldStorage::set_zero`].
    pub fn set_one(&mut self) {
        *self = Self::from_u64(1);
    }

    // ---------------------------------------------------------------- import/export

    /// Imports from 32-bit limbs, least-significant limb first, at most 8 of them.
    ///
    /// Each pair of `u32`s becomes one 64-bit limb; an odd trailing limb goes in on its own.
    /// Every limb is constrained to its literal value, so the import is bound rather than
    /// merely assigned.
    ///
    /// Returns the number of limbs consumed.
    pub fn import_u32(&mut self, limbs: &[u32]) -> usize {
        let n = limbs.len().min(2 * UINT256_NLIMBS);
        let n_full = n / 2;

        let mut g = self.inner.borrow_mut();
        g.value.realloc(UINT256_NLIMBS);

        for i in 0..n_full {
            let v = (u64::from(limbs[i * 2 + 1]) << 32) | u64::from(limbs[i * 2]);
            let limb = &mut g.value.limbs_mut()[i];
            crate::bn254fr::raw::set_u64(limb, v);
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_ff_import_u64(limb);
            crate::bn254fr::raw::assert_equal_u64(limb, v);
        }

        if n % 2 != 0 {
            let v = limbs[n_full * 2];
            let limb = &mut g.value.limbs_mut()[n_full];
            crate::bn254fr::raw::set_u32(limb, v);
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_ff_import_u32(limb);
            crate::bn254fr::raw::assert_equal_u32(limb, v);
        }

        // The C++ leaves `is_reduced_` untouched here, which claims reduced-ness for a value
        // that was never checked against the modulus. Clearing it costs a reduction on first
        // use and cannot be wrong.
        g.is_reduced = false;

        n
    }

    /// Exports to exactly `2 * UINT256_NLIMBS` 32-bit limbs, least-significant first.
    pub fn export_u32(&self, limbs: &mut [u32]) -> usize {
        assert_eq!(
            limbs.len(),
            2 * UINT256_NLIMBS,
            "invalid number of limbs to export"
        );

        let x = self.to_uint256();
        for i in 0..UINT256_NLIMBS {
            // `get_u64_checked` is the witness_cast + assert_equal_u64 pair; without it the
            // exported limbs would be host constants unbound to `x`.
            let v = crate::bn254fr::raw::get_u64_checked(x.limb(i));
            limbs[i * 2] = (v & 0xFFFF_FFFF) as u32;
            limbs[i * 2 + 1] = (v >> 32) as u32;
        }

        2 * UINT256_NLIMBS
    }

    /// Imports from little-endian bytes.
    pub fn import_bytes_little(&mut self, bytes: &[u8]) -> usize {
        let mut g = self.inner.borrow_mut();
        g.value.set_bytes_little(bytes);
        g.is_reduced = false;
        bytes.len()
    }

    /// Imports from big-endian bytes.
    pub fn import_bytes_big(&mut self, bytes: &[u8]) -> usize {
        let mut g = self.inner.borrow_mut();
        g.value.set_bytes_big(bytes);
        g.is_reduced = false;
        bytes.len()
    }

    /// Exports to exactly 32 little-endian bytes.
    pub fn export_bytes_little(&self, bytes: &mut [u8]) -> usize {
        assert_eq!(bytes.len(), 32, "invalid number of bytes to export");
        bytes.copy_from_slice(&self.to_uint256().to_bytes_little());
        32
    }

    /// Exports to exactly 32 big-endian bytes.
    pub fn export_bytes_big(&self, bytes: &mut [u8]) -> usize {
        assert_eq!(bytes.len(), 32, "invalid number of bytes to export");
        bytes.copy_from_slice(&self.to_uint256().to_bytes_big());
        32
    }

    /// Decomposes into [`PrimeField::NUM_ROUNDED_BITS`] bits, least-significant first.
    pub fn to_bits(&self) -> Vec<Bn254Fr> {
        self.to_uint256().to_bits()
    }

    /// Constrains two elements to be equal.
    pub fn assert_equal(x: &Self, y: &Self) {
        crate::uint256::assert_equal(&x.to_uint256(), &y.to_uint256());
    }

    /// Prints the value.
    pub fn print(&self) {
        self.to_uint256().print();
    }
}

/// Smallest multiple of `p` that dominates any value of the given shape, returned in overflow
/// representation.
///
/// Adding this to a value guarantees a subsequent carry-free subtraction stays non-negative.
fn calc_overflow_multiplier(
    n_limbs: usize,
    n_overflow_bits: u32,
    p: &Bn254FrBigint,
) -> Bn254FrBigint {
    debug_assert!(p.is_proper(), "p must be in proper representation");

    let max_val = Bn254FrBigint::max_proper(n_limbs, n_overflow_bits);
    let (mut q, r) = Bn254FrBigint::idiv_unchecked(&max_val, p);

    // Round up when the division was not exact.
    if !r.is_zero() {
        q = Bn254FrBigint::add_no_carry_unchecked(&q, &Bn254FrBigint::from_u64(1, 1));
    }

    let q_mul_p = Bn254FrBigint::mul_unchecked(&q, p);
    q_mul_p.to_overflow(n_limbs, n_overflow_bits + 1)
}

/// Width needed to compare `x` and `y` modulo `m`.
const fn assert_equal_mod_bits(x_bits: u32, y_bits: u32) -> u32 {
    let a = x_bits;
    let b = y_bits + 3;
    (if a > b { a } else { b }) + 1
}

/// Proves `x === 0 (mod m)` for a signed overflow value.
fn assert_equal_zero_mod(x: &Bn254FrBigint, m: &Bn254FrBigint) {
    let x_proper = x.to_proper_unchecked();
    #[allow(unused_mut)]
    let (mut q, r) = Bn254FrBigint::idiv_unchecked(&x_proper, m);
    #[cfg(feature = "fault-injection")]
    crate::fault::corrupt_ff_zero_mod(&mut q);

    let y = Bn254FrBigint::mul_no_carry(&q, m);
    let d = Bn254FrBigint::sub_no_carry(x, &y);
    let d_proper = d.to_proper();

    // Against the CONSTANT, not a fresh `Bn254Fr`. `Bn254Fr::new()` allocates and calls the
    // UNCHECKED `set_u32(0)`: the handle holds zero but nothing binds it, so a prover could
    // satisfy both loops by choosing `zero` to equal the limbs rather than the other way
    // round. Same class as A6, which fixed this in `Uint256::get_u64`. See A23.
    for limb in d_proper.limbs() {
        crate::bn254fr::raw::assert_equal_u32(limb, 0);
    }
    for limb in r.limbs() {
        crate::bn254fr::raw::assert_equal_u32(limb, 0);
    }
}

/// Proves `x === y (mod m)` for two overflow values.
fn assert_equal_mod(x: &Bn254FrBigint, y: &Bn254FrBigint, m: &Bn254FrBigint) {
    assert!(
        assert_equal_mod_bits(x.bits_count(), y.bits_count()) <= N_MAX_BITS,
        "assert_equal_mod overflow"
    );

    let mult = calc_overflow_multiplier(y.limbs_count(), y.bits_count(), m);
    let sub_res = Bn254FrBigint::sub_no_carry(&mult, y);
    let add_res = Bn254FrBigint::add_no_carry(x, &sub_res);
    assert_equal_zero_mod(&add_res, m);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assert_equal_mod_bits_matches_cpp() {
        // max(x, y + 3) + 1
        assert_eq!(assert_equal_mod_bits(100, 50), 101);
        assert_eq!(assert_equal_mod_bits(50, 100), 104);
        assert_eq!(assert_equal_mod_bits(64, 64), 68);
    }
}
