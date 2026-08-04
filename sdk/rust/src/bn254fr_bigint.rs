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

//! Arbitrary-precision integers built from [`Bn254Fr`] limbs.
//!
//! ## Overview
//!
//! This is the layer that makes *foreign* field arithmetic possible: 256-bit primes like the
//! P-256 or Ed25519 base fields do not fit in one BN254 scalar, so they are represented as
//! several 64-bit limbs and reduced explicitly. [`crate::ff`] builds prime fields on top of it,
//! and [`crate::ecc`] builds curves on top of those.
//!
//! ## Two representations
//!
//! A value is in **proper** form when it is unsigned and every limb holds at most
//! [`BASE_BITS_COUNT`] (64) bits — the canonical form. Carry-free operations (`add_no_carry`,
//! `mul_no_carry`, …) instead produce **overflow** form, where limbs may be wider or signed,
//! and defer carry propagation. Overflow limbs may grow to at most [`MAX_BITS_COUNT`] (250)
//! bits before they must be normalised, because they still have to fit in a BN254 scalar.
//! [`Bn254FrBigint::bits_count`] tracks the current bound; keeping it accurate is what keeps
//! the arithmetic sound.
//!
//! ## Checked and unchecked pairs
//!
//! Most operations come in two forms. The `_unchecked` variant asks the host to compute a
//! result out of circuit and emits **no constraints** — on its own it proves nothing. The
//! checked variant computes the same value and additionally emits the constraints that pin it
//! down. Nearly every checked operation here is built as "call the oracle, then prove the
//! answer": `idiv` proves `q*b + r == a` and `r < b`, `invmod` proves `a * a^-1 == 1 (mod m)`,
//! and so on. **Porting only the unchecked half of a pair silently destroys soundness.**
//!
//! ## Layering
//!
//! [`Bn254FrBigint`] is the entire public bigint API, exactly as [`Bn254Fr`] is the entire
//! public scalar API — a caller never handles limbs, just as it never handles a `bn254fr_t`
//! handle. The slice-of-`Bn254Fr` host wrappers at the bottom of this file, and the
//! constraint-emitting helpers that pair with them, are private for that reason.

use crate::bn254fr::{self, assert_equal_u32, bn254fr_t, ceil_log2, raw, Bn254Fr};

/// Bits per limb in proper representation.
pub const BASE_BITS_COUNT: u32 = 64;

/// Maximum bits a single overflow limb may hold before it must be normalised.
pub const MAX_BITS_COUNT: u32 = 250;

/// Bytes per limb in proper representation.
const LIMB_BYTES: usize = (BASE_BITS_COUNT / 8) as usize;

/// Number of limbs a proper representation needs for an overflow value with
/// `n_overflow_bits` bits per limb.
pub const fn proper_size(n_limbs: usize, n_bits: u32, n_overflow_bits: u32) -> usize {
    if n_overflow_bits == n_bits {
        n_limbs
    } else {
        n_limbs + (n_overflow_bits / n_bits) as usize
    }
}

/// Result width of `mul_checked_no_carry` for the given operand shapes.
pub const fn mul_checked_no_carry_bits(
    a_limbs: usize,
    a_bits: u32,
    b_limbs: usize,
    b_bits: u32,
) -> u32 {
    let min_limbs = if a_limbs < b_limbs { a_limbs } else { b_limbs };
    a_bits + b_bits + ceil_log2(min_limbs as u32)
}

/// Proves that `out` is the proper representation of the unsigned value `in`.
///
/// Propagates carries limb by limb, range-checking each one, and asserts the final carry
/// lands in `out[count]`.xw
fn range_check(inp: &[bn254fr_t], out: &[bn254fr_t], n_bits: u32, max_terms: usize) {
    let count = inp.len();
    assert_eq!(out.len(), count + 1, "range_check: out must be count + 1");

    for limb in out.iter().take(count) {
        raw::check_bits(limb, n_bits);
    }

    let mut n_bits_pow = raw::Tmp::from_u32(1);
    { let _sh = raw::Tmp::from_u32(n_bits); let _src = raw::Tmp::from_u32(1); raw::shlmod(&mut n_bits_pow, &_src, &_sh); }

    let n_carry_bits = n_bits + ceil_log2(max_terms as u32);

    let mut running_carry: Vec<raw::Tmp> = Vec::with_capacity(count);

    // carry[0] = (in[0] - out[0]) / 2^n_bits
    {
        let mut carry_diff = raw::Tmp::new();
        raw::submod_checked(&mut carry_diff, &inp[0], &out[0]);
        let mut c = raw::Tmp::new();
        raw::divmod_constant_checked(&mut c, &carry_diff, &n_bits_pow);
        raw::check_bits(&c, n_carry_bits);
        running_carry.push(c);
    }

    // carry[i] = (in[i] - out[i] + carry[i-1]) / 2^n_bits
    for i in 1..count {
        let mut tmp = raw::Tmp::new();
        raw::submod_checked(&mut tmp, &inp[i], &out[i]);
        let mut carry_diff = raw::Tmp::new();
        raw::addmod_checked(&mut carry_diff, &tmp, &running_carry[i - 1]);

        let mut c = raw::Tmp::new();
        raw::divmod_constant_checked(&mut c, &carry_diff, &n_bits_pow);
        raw::check_bits(&c, n_carry_bits);
        running_carry.push(c);
    }

    raw::assert_equal(&out[count], &running_carry[count - 1]);
}

/// Proves that `out` is the proper representation of the signed value `in`.
///
/// Differs from [`range_check`] in four ways that all matter: the shift comes from `shlmod`
/// rather than a power, the carry width is a fixed point rather than a sum over limbs, the
/// difference is taken as `out[i] - in[i]` (reversed), and the **final carry is asserted
/// zero** rather than stored.
fn range_check_signed(inp: &[bn254fr_t], out: &[bn254fr_t], in_bits: u32, out_bits: u32) {
    let in_count = inp.len();
    let out_count = out.len();

    for limb in out.iter() {
        raw::check_bits(limb, out_bits);
    }

    let mut n_bits_pow = raw::Tmp::from_u32(1);
    { let _sh = raw::Tmp::from_u32(out_bits); let _src = raw::Tmp::from_u32(1); raw::shlmod(&mut n_bits_pow, &_src, &_sh); }

    let n_carry_bits = if in_bits > out_bits + 1 {
        in_bits - out_bits + 1
    } else {
        3
    };

    // running_carry = (out[0] - in[0]) / 2^out_bits
    let mut running_carry = raw::Tmp::new();
    {
        let mut carry_diff = raw::Tmp::new();
        raw::submod_checked(&mut carry_diff, &out[0], &inp[0]);
        raw::divmod_constant_checked(&mut running_carry, &carry_diff, &n_bits_pow);
        raw::check_bits_signed(&running_carry, n_carry_bits);
    }

    for i in 1..out_count {
        let mut tmp = raw::Tmp::new();
        if i < in_count {
            raw::submod_checked(&mut tmp, &out[i], &inp[i]);
        } else {
            raw::copy(&mut tmp, &out[i]);
            // This assertion is NOT isolatable, and both escape routes were measured. Skewing
            // `tmp` (as here) also breaks the carry chain and its terminal "last carry must
            // vanish" check. Skewing `out[i]` instead falsifies the `check_bits` this function
            // already applied to every out limb at its top. Either way the proof fails for a
            // second reason, so deleting the assertion below goes unnoticed. See A22.
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_bigint_signed_copy(&mut tmp);
            raw::assert_equal(&tmp, &out[i]);
        }

        let mut carry_diff = raw::Tmp::new();
        raw::addmod_checked(&mut carry_diff, &tmp, &running_carry);

        let mut new_carry = raw::Tmp::new();
        raw::divmod_constant_checked(&mut new_carry, &carry_diff, &n_bits_pow);
        running_carry = new_carry;

        raw::check_bits_signed(&running_carry, n_carry_bits);
    }

    // The last running carry must vanish -- against the CONSTANT. A fresh `Tmp` is an
    // unconstrained witness, so comparing to one proved nothing at all and this terminal check,
    // the whole point of the signed conversion, was vacuous. See A26.
    raw::assert_equal_u32(&running_carry, 0);
}

/// Converts a signed overflow value to proper representation **with** constraints.
fn convert_to_proper_representation_signed_checked(
    out: &mut [bn254fr_t],
    inp: &[bn254fr_t],
    out_bits: u32,
    in_bits: u32,
) {
    bigint_convert_to_proper_representation_signed(out, inp, out_bits);
    range_check_signed(inp, out, in_bits, out_bits);
}

/// Arbitrary-precision integer over [`Bn254Fr`] limbs, least-significant limb first.
pub struct Bn254FrBigint {
    /// Contiguous handles, as the host API requires. A `Vec<raw::Tmp>` would give a
    /// 16-byte stride the C API's `bn254fr_t*` cannot consume, forcing the handle marshalling
    /// that used to leak host pointers into the proof. See [`crate::bn254fr::raw`].
    limbs: Vec<bn254fr_t>,
    bits_count: u32,
    is_unsigned: bool,
}

impl Drop for Bn254FrBigint {
    fn drop(&mut self) {
        for limb in &mut self.limbs {
            raw::free(limb);
        }
    }
}

impl Default for Bn254FrBigint {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Bn254FrBigint {
    /// Copies the value **and emits an equality constraint per limb**, unconditionally.
    ///
    /// This is not free, but the reduction path relies on it.
    /// Note it differs from [`Bn254Fr::clone`], which only constrains when the source is
    /// already constrained.
    fn clone(&self) -> Self {
        let mut out = Self::with_limbs(self.limbs.len());
        for (dst, src) in out.limbs.iter_mut().zip(self.limbs.iter()) {
            raw::copy(dst, src);
            raw::assert_equal(dst, src);
        }
        out.bits_count = self.bits_count;
        out.is_unsigned = self.is_unsigned;
        out
    }
}

impl Bn254FrBigint {
    // ---------------------------------------------------------------- construction

    /// Zero with no allocated limbs.
    pub fn new() -> Self {
        Self {
            limbs: Vec::new(),
            bits_count: BASE_BITS_COUNT,
            is_unsigned: true,
        }
    }

    /// Zero with `n_limbs` allocated limbs.
    pub fn with_limbs(n_limbs: usize) -> Self {
        let mut limbs = vec![bn254fr_t::default(); n_limbs];
        for limb in &mut limbs {
            raw::alloc(limb);
        }
        Self {
            limbs,
            bits_count: BASE_BITS_COUNT,
            is_unsigned: true,
        }
    }

    /// `n_limbs` limbs holding the value `val`.
    pub fn from_u64(n_limbs: usize, val: u64) -> Self {
        let mut res = Self::with_limbs(n_limbs);
        if n_limbs > 0 {
            raw::set_u64(&mut res.limbs[0], val);
        }
        res
    }

    /// Builds from existing limbs, adding an equality constraint for each.
    pub(crate) fn from_limbs_checked(
        limbs: &[bn254fr_t],
        n_bits: u32,
        is_unsigned: bool,
    ) -> Self {
        let mut res = Self::with_limbs(limbs.len());
        for (dst, src) in res.limbs.iter_mut().zip(limbs.iter()) {
            raw::copy(dst, src);
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_bigint_from_limbs(dst);
            raw::assert_equal(dst, src);
        }
        res.bits_count = n_bits;
        res.is_unsigned = is_unsigned;
        res
    }

    // ---------------------------------------------------------------- accessors

    pub fn limbs_count(&self) -> usize {
        self.limbs.len()
    }

    pub fn bits_count(&self) -> u32 {
        self.bits_count
    }

    pub fn set_bits_count(&mut self, count: u32) {
        self.bits_count = count;
    }

    pub fn is_unsigned(&self) -> bool {
        self.is_unsigned
    }

    pub fn set_unsigned(&mut self, u: bool) {
        self.is_unsigned = u;
    }

    /// True when this value is in proper (canonical) representation.
    pub fn is_proper(&self) -> bool {
        self.is_unsigned && self.bits_count == BASE_BITS_COUNT
    }

    /// The limbs themselves, least-significant first.
    ///
    /// Crate-internal: handing out limbs would let a caller do bigint arithmetic without this
    /// type,
    /// which is the thing the encapsulation is for. The field and curve layers are in-crate,
    /// so they are unaffected.
    pub(crate) fn limbs(&self) -> &[bn254fr_t] {
        &self.limbs
    }

    /// Mutable limb access, for the in-crate operations that write limb by limb —
    /// `PrimeFieldStorage::mux` and `uint256::mul_wide`. See [`Bn254FrBigint::limbs`] on why
    /// this is not public.
    ///
    /// Writing through this does **not** update [`Bn254FrBigint::bits_count`]; the caller
    /// owns keeping that bound accurate.
    pub(crate) fn limbs_mut(&mut self) -> &mut [bn254fr_t] {
        &mut self.limbs
    }


    /// Replaces the limbs, adding an equality constraint for each.
    pub(crate) fn set(&mut self, limbs: &[bn254fr_t], n_bits: u32, is_unsigned: bool) {
        self.realloc(limbs.len());
        for (dst, src) in self.limbs.iter_mut().zip(limbs.iter()) {
            raw::copy(dst, src);
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_bigint_set(dst);
            raw::assert_equal(dst, src);
        }
        self.bits_count = n_bits;
        self.is_unsigned = is_unsigned;
    }

    /// Reallocates to `count` fresh zero limbs. Does not reset the width flags.
    pub fn realloc(&mut self, count: usize) {
        for limb in &mut self.limbs {
            raw::free(limb);
        }
        self.limbs = vec![bn254fr_t::default(); count];
        for limb in &mut self.limbs {
            raw::alloc(limb);
        }
    }

    // ---------------------------------------------------------------- debug

    pub fn print(&self) {
        bigint_print(&self.limbs, BASE_BITS_COUNT);
    }

    pub fn dump(&self) {
        self.print();
        for limb in &self.limbs {
            raw::print(limb, 10);
        }
    }

    // ---------------------------------------------------------------- predicates

    /// Host-side zero test. Adds **no** constraints and branches on the concrete value, so it
    /// must never be applied to secret data.
    pub fn is_zero(&self) -> bool {
        let zero = raw::Tmp::from_u32(0);
        self.limbs.iter().all(|limb| raw::eq(limb, &zero))
    }

    /// Circuit boolean: 1 when every limb is zero.
    pub fn eqz(&self) -> Bn254Fr {
        let zero = raw::Tmp::new();
        let mut sum = raw::Tmp::new();

        for limb in &self.limbs {
            let mut eq = raw::Tmp::new();
            raw::eq_checked(&mut eq, limb, &zero);

            let mut tmp = raw::Tmp::new();
            raw::addmod_checked(&mut tmp, &sum, &eq);
            sum = tmp;
        }

        let exp_sum = raw::Tmp::from_u32(self.limbs_count() as u32);
        let mut res = Bn254Fr::new();
        raw::eq_checked(res.handle_mut(), &sum, &exp_sum);
        res
    }

    /// Circuit boolean: 1 when `a == b`. Limbs beyond the shorter operand must be zero.
    pub fn eq(a: &Self, b: &Self) -> Bn254Fr {
        let zero = raw::Tmp::new();
        let mut sum = raw::Tmp::new();

        let a_count = a.limbs_count();
        let b_count = b.limbs_count();
        let common = a_count.min(b_count);

        let accumulate = |sum: &mut raw::Tmp, x: &bn254fr_t, y: &bn254fr_t| {
            let mut eq = raw::Tmp::new();
            raw::eq_checked(&mut eq, x, y);
            let mut tmp = raw::Tmp::new();
            raw::addmod_checked(&mut tmp, sum, &eq);
            *sum = tmp;
        };

        for i in 0..common {
            accumulate(&mut sum, &a.limbs[i], &b.limbs[i]);
        }
        for i in common..b_count {
            accumulate(&mut sum, &b.limbs[i], &zero);
        }
        for i in common..a_count {
            accumulate(&mut sum, &a.limbs[i], &zero);
        }

        let exp_sum = raw::Tmp::from_u32(a_count.max(b_count) as u32);
        let mut res = Bn254Fr::new();
        raw::eq_checked(res.handle_mut(), &sum, &exp_sum);
        res
    }

    /// Circuit boolean: 1 when `a < b`. Both operands must be proper and equally sized.
    ///
    /// Compares limb-wise from the most significant end: the result is
    /// `lt[n-1] | (eq[n-1] & lt[n-2]) | (eq[n-1] & eq[n-2] & lt[n-3]) | …`.
    pub fn lt(a: &Self, b: &Self) -> Bn254Fr {
        assert!(
            a.is_proper() && b.is_proper(),
            "bn254fr_bigint::lt requires proper representation"
        );
        assert_eq!(
            a.limbs_count(),
            b.limbs_count(),
            "bn254fr_bigint::lt requires equal limb counts"
        );

        lt_checked_limbs(&a.limbs, &b.limbs, BASE_BITS_COUNT)
    }

    // ---------------------------------------------------------------- bounds

    /// Largest value representable with `n_limbs` limbs of `n_bits` bits each.
    pub fn max(n_limbs: usize, n_bits: u32) -> Self {
        // pow_2 = 2^n_bits - 1, computed without constraints.
        let mut pow_2 = raw::Tmp::from_u32(1);
        { let _sh = raw::Tmp::from_u32(n_bits); let _src = raw::Tmp::from_u32(1); raw::shlmod(&mut pow_2, &_src, &_sh); }
        let one = raw::Tmp::from_u32(1);
        let mut limb_max = raw::Tmp::new();
        raw::submod(&mut limb_max, &pow_2, &one);

        let mut res = Self::with_limbs(n_limbs);
        res.bits_count = n_bits;
        for limb in res.limbs.iter_mut() {
            raw::copy(limb, &limb_max);
        }
        res
    }

    /// [`Bn254FrBigint::max`] converted to proper representation, unconstrained.
    pub fn max_proper(n_limbs: usize, n_bits: u32) -> Self {
        Self::max(n_limbs, n_bits).to_proper_unchecked()
    }

    // ---------------------------------------------------------------- representation

    /// Converts to proper representation **with** constraints.
    pub fn to_proper(&self) -> Self {
        if self.is_proper() {
            // Still a constraint-emitting copy: the caller relies on those constraints.
            return self.clone();
        }

        let res_size = proper_size(self.limbs_count(), BASE_BITS_COUNT, self.bits_count);
        let mut res = Self::with_limbs(res_size);

        // Unsigned values still go through the signed conversion, one bit wider.
        let bcount = if self.is_unsigned {
            self.bits_count + 1
        } else {
            self.bits_count
        };

        convert_to_proper_representation_signed_checked(
            &mut res.limbs,
            &self.limbs,
            BASE_BITS_COUNT,
            bcount,
        );
        res
    }

    /// Converts to proper representation **without** constraints.
    pub fn to_proper_unchecked(&self) -> Self {
        if self.is_proper() {
            return self.clone();
        }

        let res_size = proper_size(self.limbs_count(), BASE_BITS_COUNT, self.bits_count);
        let mut res = Self::with_limbs(res_size);

        if self.is_unsigned {
            bigint_convert_to_proper_representation_unsigned(
                &mut res.limbs,
                &self.limbs,
                BASE_BITS_COUNT,
            );
        } else {
            bigint_convert_to_proper_representation_signed(
                &mut res.limbs,
                &self.limbs,
                BASE_BITS_COUNT,
            );
        }
        res
    }

    /// Converts to overflow representation with `n_limbs` limbs of `n_bits` bits each.
    pub fn to_overflow(&self, n_limbs: usize, n_bits: u32) -> Self {
        let mut res = Self::with_limbs(n_limbs);
        res.bits_count = n_bits;
        bigint_convert_to_overflow_representation(
            &mut res.limbs,
            &self.limbs,
            BASE_BITS_COUNT,
            n_bits,
        );
        res
    }

    // ---------------------------------------------------------------- byte import

    /// Sets the value from little-endian bytes, with constraints.
    pub fn set_bytes_little(&mut self, bytes: &[u8]) {
        let sz = bytes.len();
        let n_limbs = sz.div_ceil(LIMB_BYTES);
        self.realloc(n_limbs);

        let n_full = sz / LIMB_BYTES;
        for i in 0..n_full {
            set_bytes_checked(
                &mut self.limbs[i],
                &bytes[i * LIMB_BYTES..(i + 1) * LIMB_BYTES],
                bn254fr::ORDER_LITTLE,
            );
        }

        let rem = sz % LIMB_BYTES;
        if rem != 0 {
            set_bytes_checked(
                &mut self.limbs[n_full],
                &bytes[n_full * LIMB_BYTES..],
                bn254fr::ORDER_LITTLE,
            );
        }

        self.bits_count = BASE_BITS_COUNT;
        self.is_unsigned = true;
    }

    /// Sets the value from big-endian bytes, with constraints.
    ///
    /// The partial chunk is the *most* significant one here, so it lands in the highest limb
    /// and the full chunks fill downwards.
    pub fn set_bytes_big(&mut self, bytes: &[u8]) {
        let sz = bytes.len();
        let n_limbs = sz.div_ceil(LIMB_BYTES);
        self.realloc(n_limbs);

        let n_full = sz / LIMB_BYTES;
        let rem = sz % LIMB_BYTES;

        // A leading partial group is the most significant limb.
        if rem != 0 {
            set_bytes_checked(&mut self.limbs[n_limbs - 1], &bytes[..rem], bn254fr::ORDER_BIG);
        }

        // The full groups fill the limbs below it, most significant first. Indexing from
        // `n_full` rather than `n_limbs` is what keeps the partial limb intact: when
        // `rem != 0` the two differ by one, and using `n_limbs` here would overwrite the limb
        // just written above and leave limb 0 at zero — shifting the whole value up by 64 bits
        // and dropping its leading bytes. The C++ `bn254fr_bigint::set_bytes_big` still has
        // that form. When `rem == 0` the two indices coincide, so nothing changes for the
        // 32-byte case every caller in this SDK uses.
        for i in 0..n_full {
            let start = rem + i * LIMB_BYTES;
            set_bytes_checked(
                &mut self.limbs[n_full - i - 1],
                &bytes[start..start + LIMB_BYTES],
                bn254fr::ORDER_BIG,
            );
        }

        self.bits_count = BASE_BITS_COUNT;
        self.is_unsigned = true;
    }

    // ---------------------------------------------------------------- arithmetic

    /// Result width of [`Bn254FrBigint::add_no_carry`].
    pub fn add_no_carry_res_bits_count(x: &Self, y: &Self) -> u32 {
        x.bits_count.max(y.bits_count) + 1
    }

    /// Carry-free addition, **with** constraints.
    pub fn add_no_carry(x: &Self, y: &Self) -> Self {
        let res_bits = Self::add_no_carry_res_bits_count(x, y);
        assert!(res_bits <= MAX_BITS_COUNT, "bn254fr bigint overflow");
        Self::add_no_carry_impl(x, y, res_bits, true)
    }

    /// Carry-free addition, **without** constraints.
    pub fn add_no_carry_unchecked(x: &Self, y: &Self) -> Self {
        let res_bits = Self::add_no_carry_res_bits_count(x, y);
        assert!(res_bits <= MAX_BITS_COUNT, "bn254fr bigint overflow");
        Self::add_no_carry_impl(x, y, res_bits, false)
    }

    fn add_no_carry_impl(x: &Self, y: &Self, res_bits: u32, checked: bool) -> Self {
        let x_count = x.limbs_count();
        let y_count = y.limbs_count();
        let common = x_count.min(y_count);

        let mut res = Self::with_limbs(x_count.max(y_count));

        for i in 0..common {
            if checked {
                raw::addmod_checked(&mut res.limbs[i], &x.limbs[i], &y.limbs[i]);
            } else {
                raw::addmod(&mut res.limbs[i], &x.limbs[i], &y.limbs[i]);
            }
        }

        // Surplus limbs are copied across, constrained only in the checked form.
        let (src, range) = if x_count > y_count {
            (x, y_count..x_count)
        } else {
            (y, x_count..y_count)
        };
        for i in range {
            raw::copy(&mut res.limbs[i], &src.limbs[i]);
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_bigint_add_surplus(&mut res.limbs[i]);
            if checked {
                raw::assert_equal(&res.limbs[i], &src.limbs[i]);
            }
        }

        res.is_unsigned = x.is_unsigned && y.is_unsigned;
        res.bits_count = res_bits;
        res
    }

    /// Addition **with** carry propagation and constraints, staying in proper representation.
    ///
    /// Unlike [`Bn254FrBigint::add_no_carry`] this does not defer carries: every limb is
    /// reduced to `BASE_BITS_COUNT` bits as it is produced, and the result is one limb wider
    /// than the wider operand so the final carry has somewhere to land. Both operands must
    /// already be proper.
    pub fn add_checked(x: &Self, y: &Self) -> Self {
        assert!(
            x.is_proper() && y.is_proper(),
            "bn254fr_bigint::add_checked requires proper representation"
        );

        let x_count = x.limbs_count();
        let y_count = y.limbs_count();
        let common = x_count.min(y_count);
        let wider = x_count.max(y_count);

        let mut res = Self::with_limbs(wider + 1);
        let n_bits = BASE_BITS_COUNT;

        // First limb: a plain two-operand add, since there is no carry in yet.
        let mut carry = add_checked_with_carry(&mut res.limbs[0], &x.limbs[0], &y.limbs[0], n_bits);

        // Limbs both operands have: three-operand add folding the running carry.
        for i in 1..common {
            carry =
                add_3_checked_with_carry(&mut res.limbs[i], &x.limbs[i], &y.limbs[i], &carry, n_bits);
        }

        // Limbs only the wider operand has: still needs the carry chain.
        let longer = if x_count > y_count { x } else { y };
        for i in common..wider {
            carry = add_checked_with_carry(&mut res.limbs[i], &longer.limbs[i], &carry, n_bits);
        }

        // The final carry becomes the top limb.
        raw::copy(&mut res.limbs[wider], &carry);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_bigint_add_carry(&mut res.limbs[wider]);
        raw::assert_equal(&res.limbs[wider], &carry);

        res
    }

    /// Result width of [`Bn254FrBigint::sub_no_carry`].
    pub fn sub_no_carry_res_bits_count(x: &Self, y: &Self) -> u32 {
        (x.bits_count + 1).max(y.bits_count) + 1
    }

    /// Carry-free subtraction, **with** constraints. The result is signed.
    ///
    /// Emits no overflow assertion of its own — `add_no_carry`'s assertion is the real
    /// backstop for the composite `sub` in the field layer.
    pub fn sub_no_carry(x: &Self, y: &Self) -> Self {
        let x_count = x.limbs_count();
        let y_count = y.limbs_count();

        let mut res = Self::with_limbs(x_count.max(y_count));
        res.bits_count = Self::sub_no_carry_res_bits_count(x, y);
        res.is_unsigned = false;

        let common = x_count.min(y_count);
        for i in 0..common {
            raw::submod_checked(&mut res.limbs[i], &x.limbs[i], &y.limbs[i]);
        }

        if x_count >= y_count {
            for i in y_count..x_count {
                raw::copy(&mut res.limbs[i], &x.limbs[i]);
                #[cfg(feature = "fault-injection")]
                crate::fault::corrupt_bigint_sub_surplus(&mut res.limbs[i]);
                raw::assert_equal(&res.limbs[i], &x.limbs[i]);
            }
        } else {
            for i in x_count..y_count {
                raw::negmod_checked(&mut res.limbs[i], &y.limbs[i]);
            }
        }

        res
    }

    /// Result width of [`Bn254FrBigint::mul_no_carry`].
    pub fn mul_no_carry_res_bits_count(x: &Self, y: &Self) -> u32 {
        x.bits_count + y.bits_count + ceil_log2(x.limbs_count().min(y.limbs_count()) as u32)
    }

    /// Carry-free multiplication, **with** constraints.
    pub fn mul_no_carry(x: &Self, y: &Self) -> Self {
        let res_limbs = x.limbs_count() + y.limbs_count() - 1;
        let mut res = Self::with_limbs(res_limbs);
        res.bits_count = Self::mul_no_carry_res_bits_count(x, y);
        bigint_mul_checked_no_carry(&mut res.limbs, &x.limbs, &y.limbs);
        res
    }

    /// Multiplication **without** constraints. Note this uses one more limb than
    /// [`Bn254FrBigint::mul_no_carry`].
    pub fn mul_unchecked(x: &Self, y: &Self) -> Self {
        let mut res = Self::with_limbs(x.limbs_count() + y.limbs_count());
        bigint_mul(&mut res.limbs, &x.limbs, &y.limbs, BASE_BITS_COUNT);
        res
    }

    /// Multiplication **with** carry propagation and constraints, in proper representation.
    ///
    /// The three-step composition that makes a carry-propagated product sound:
    /// [`Bn254FrBigint::mul_no_carry`] for the constrained overflow product, the host oracle
    /// to propagate carries, then [`range_check`] to prove the oracle's answer is the same
    /// integer. Dropping the third step is what leaves the result a free witness — see the
    /// note on [`range_check`].
    ///
    /// Result is `x.limbs_count() + y.limbs_count()` limbs wide.
    pub fn mul_checked(x: &Self, y: &Self) -> Self {
        assert!(
            x.is_proper() && y.is_proper(),
            "bn254fr_bigint::mul_checked requires proper representation"
        );

        let mut no_carry = Self::mul_no_carry(x, y);

        let mut res = Self::with_limbs(no_carry.limbs_count() + 1);
        bigint_convert_to_proper_representation(
            &mut res.limbs,
            &mut no_carry.limbs,
            BASE_BITS_COUNT,
        );

        // Test-only seam: skews the top limb, which range_check pins by equality alone.
        #[cfg(feature = "fault-injection")]
        {
            let last = res.limbs.len() - 1;
            crate::fault::corrupt_bigint_proper_top(&mut res.limbs[last]);
        }

        // Without this the limbs above are unconstrained witnesses.
        range_check(&no_carry.limbs, &res.limbs, BASE_BITS_COUNT,
                    x.limbs_count().min(y.limbs_count()));

        res
    }

    /// Integer division **without** constraints. Returns `(quotient, remainder)`.
    pub fn idiv_unchecked(x: &Self, y: &Self) -> (Self, Self) {
        let mut q = Self::with_limbs(x.limbs_count());
        let mut r = Self::with_limbs(y.limbs_count());
        bigint_idiv(&mut q.limbs, &mut r.limbs, &x.limbs, &y.limbs, BASE_BITS_COUNT);
        (q, r)
    }

    /// Integer division **with** constraints, proving `q*b + r == a` and `r < b`.
    pub fn idiv(a: &Self, b: &Self) -> (Self, Self) {
        #[allow(unused_mut)]
        let (mut q, mut r) = Self::idiv_unchecked(a, b);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_bigint_idiv(&mut q, &mut r, b);

        for limb in q.limbs() {
            raw::check_bits(limb, BASE_BITS_COUNT);
        }
        for limb in r.limbs() {
            raw::check_bits(limb, BASE_BITS_COUNT);
        }

        let mul_res = Self::mul_no_carry(&q, b);
        let add_res = Self::add_no_carry(&mul_res, &r);
        let add_res_prop = add_res.to_proper();

        for i in 0..a.limbs_count() {
            raw::assert_equal(&a.limbs[i], &add_res_prop.limbs[i]);
        }
        // Against the CONSTANT: a fresh `Tmp` is a free witness the prover could set to the
        // common value of these limbs. See A26.
        for i in a.limbs_count()..add_res_prop.limbs_count() {
            raw::assert_equal_u32(&add_res_prop.limbs[i], 0);
        }

        let lt_res = Self::lt(&r, b);
        assert_equal_u32(&lt_res, 1);

        (q, r)
    }

    /// Remainder **without** constraints.
    pub fn rem_unchecked(a: &Self, m: &Self) -> Self {
        Self::idiv_unchecked(a, m).1
    }

    /// Remainder **with** constraints.
    ///
    /// Note the deliberate operand mixing: the quotient comes from the *proper* forms, but the
    /// verification multiplies by the original `m` and subtracts from the original `a`.
    pub fn rem(a: &Self, m: &Self) -> Self {
        let a_prop = a.to_proper_unchecked();
        let m_prop = m.to_proper_unchecked();

        #[allow(unused_mut)]
        let (mut q, mut out) = Self::idiv_unchecked(&a_prop, &m_prop);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_bigint_rem(&mut q, &mut out, &m_prop);

        // out < m
        let lt_res = Self::lt(&out, &m_prop);
        assert_equal_u32(&lt_res, 1);

        // q * m + out === a
        let mul_res = Self::mul_no_carry(&q, m);
        let add_res = Self::add_no_carry(&mul_res, &out);
        let sub_res = Self::sub_no_carry(a, &add_res);
        let sub_res_proper = sub_res.to_proper();

        // Against the CONSTANT, not a fresh handle. `raw::Tmp::new()` allocates and calls the
        // UNCHECKED `set_u32(0)`, so the handle holds zero but is a free witness -- a prover
        // could satisfy `limb == zero` by choosing `zero` to match the limbs instead. Same
        // class as A6, which fixed this in `Uint256::get_u64`. See A23.
        for limb in sub_res_proper.limbs() {
            raw::assert_equal_u32(limb, 0);
        }

        out
    }

    /// Modular inverse **without** constraints.
    pub fn invmod_unchecked(a: &Self, m: &Self) -> Self {
        let mut res = Self::with_limbs(m.limbs_count());
        bigint_invmod(&mut res.limbs, &a.limbs, &m.limbs, BASE_BITS_COUNT);
        res
    }

    /// Modular inverse **with** constraints, proving `a * a^-1 == 1 (mod m)`.
    pub fn invmod(a: &Self, m: &Self) -> Self {
        #[allow(unused_mut)]
        let mut res = Self::invmod_unchecked(a, m);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_bigint_invmod(&mut res, m);

        let mul_res = Self::mul_no_carry(&res, a);
        let mul_res_rem = Self::rem(&mul_res, m);

        raw::assert_equal_u32(&mul_res_rem.limbs[0], 1);
        // See the note in `rem`: a fresh handle is an unconstrained witness, so the higher
        // limbs must be pinned to the constant. With `zero` free a prover could target
        // `res * a mod m == 1 + k*(2^64 + 2^128 + ...)` and pass `zero = k`.
        for limb in mul_res_rem.limbs().iter().skip(1) {
            raw::assert_equal_u32(limb, 0);
        }

        res
    }
}

/// `a + b` reduced to `n_bits`, plus the 1-bit carry out.
///
/// Adds the two values in the full BN254 field, decomposes the sum into `n_bits + 1` bits, and
/// splits: the top bit is the carry, the rest recompose into the reduced limb. The
/// decomposition is what constrains both halves.
fn add_checked_with_carry(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t, n_bits: u32) -> raw::Tmp {
    let mut sum = raw::Tmp::new();
    raw::addmod_checked(&mut sum, a, b);
    raw::split_carry(out, &sum, n_bits)
}

/// `a + b + c` reduced to `n_bits`, plus the 1-bit carry out. `c` must be a single bit.
fn add_3_checked_with_carry(
    out: &mut bn254fr_t,
    a: &bn254fr_t,
    b: &bn254fr_t,
    c: &bn254fr_t,
    n_bits: u32,
) -> raw::Tmp {
    let mut sum = raw::Tmp::new();
    raw::addmod_checked(&mut sum, a, b);
    let mut sum3 = raw::Tmp::new();
    raw::addmod_checked(&mut sum3, &sum, c);
    raw::split_carry(out, &sum3, n_bits)
}

/// `2^n_bits`, as an unconstrained constant.
fn pow_2(n_bits: u32) -> raw::Tmp {
    let mut p = raw::Tmp::from_u32(1);
    let sh = raw::Tmp::from_u32(n_bits);
    let src = raw::Tmp::from_u32(1);
    raw::shlmod(&mut p, &src, &sh);
    p
}

/// `a - b` reduced to `n_bits`, with the 1-bit borrow written into `borrow`.
///
/// Adds `2^n_bits` first so the difference cannot go negative, then decomposes into `n_bits + 1`
/// bits. The top bit is set exactly when no borrow occurred, so the borrow is its complement.
///
/// The borrow is an out-param rather than a return value so the last limb of a chain can write
/// it straight into the caller's underflow handle. See [`sub_checked_limbs`].
fn sub_checked_with_borrow(
    out: &mut bn254fr_t,
    borrow: &mut bn254fr_t,
    a: &bn254fr_t,
    b: &bn254fr_t,
    n_bits: u32,
) {
    let mut diff = raw::Tmp::new();
    raw::submod_checked(&mut diff, a, b);

    let mut sum = raw::Tmp::new();
    raw::addmod_checked(&mut sum, &pow_2(n_bits), &diff);

    let msb = raw::split_carry(out, &sum, n_bits);
    let one = raw::Tmp::from_u32(1);
    raw::submod_checked(borrow, &one, &msb);
}

/// `a - b - c` reduced to `n_bits`, with the 1-bit borrow written into `borrow`. `c` must be a
/// single bit.
fn sub_3_checked_with_borrow(
    out: &mut bn254fr_t,
    borrow: &mut bn254fr_t,
    a: &bn254fr_t,
    b: &bn254fr_t,
    c: &bn254fr_t,
    n_bits: u32,
) {
    let mut bc = raw::Tmp::new();
    raw::addmod_checked(&mut bc, b, c);

    let mut diff = raw::Tmp::new();
    raw::submod_checked(&mut diff, a, &bc);

    let mut sum = raw::Tmp::new();
    raw::addmod_checked(&mut sum, &pow_2(n_bits), &diff);

    let msb = raw::split_carry(out, &sum, n_bits);
    let one = raw::Tmp::from_u32(1);
    raw::submod_checked(borrow, &one, &msb);
}

/// Sets a field element from bytes and constrains it to them.
fn set_bytes_checked(out: &mut bn254fr_t, bytes: &[u8], order: i32) {
    raw::set_bytes_checked(out, bytes, order);
}

// ============================================================================
// Host import tier
//
// The wrappers below marshal `Bn254Fr` limbs into contiguous `u64` handle arrays for the
// host. They are the Rust counterpart of the C-level `bn254fr_bigint_*(bn254fr_t*, …,
// uint32_t count)` API in `bn254fr.h`, and they are private for the same reason `bn254fr_t`
// is: [`Bn254FrBigint`] is the whole public bigint interface, so nothing outside this module
// should be handling limbs.
// ============================================================================

/// `out = a + b` with carries propagated, over raw limb slices.
///
/// The slice-level counterpart of [`Bn254FrBigint::add_checked`], for callers that already
/// hold contiguous limbs. `out` must have `max(a, b) + 1` limbs.
pub(crate) fn add_checked_limbs(
    out: &mut [bn254fr_t],
    a: &[bn254fr_t],
    b: &[bn254fr_t],
    n_bits: u32,
) {
    let common = a.len().min(b.len());
    let wider = a.len().max(b.len());
    assert_eq!(out.len(), wider + 1, "add_checked_limbs: bad out width");

    let mut carry = add_checked_with_carry(&mut out[0], &a[0], &b[0], n_bits);
    for i in 1..common {
        carry = add_3_checked_with_carry(&mut out[i], &a[i], &b[i], &carry, n_bits);
    }
    let longer = if a.len() > b.len() { a } else { b };
    for i in common..wider {
        carry = add_checked_with_carry(&mut out[i], &longer[i], &carry, n_bits);
    }

    raw::copy(&mut out[wider], &carry);
    raw::assert_equal(&out[wider], &carry);
}

/// `out = a - b` with borrows propagated, over raw limb slices.
///
/// The structural mirror of [`add_checked_limbs`]. There is no `Bn254FrBigint`-level sibling:
/// the object API subtracts without carries ([`Bn254FrBigint::sub_no_carry`]) and normalises
/// later. `a` and `b` must be the same width; `out` needs one limb more, and that limb receives
/// the final borrow -- the underflow flag.
pub(crate) fn sub_checked_limbs(
    out: &mut [bn254fr_t],
    a: &[bn254fr_t],
    b: &[bn254fr_t],
    n_bits: u32,
) {
    assert_eq!(a.len(), b.len(), "sub_checked_limbs: operands differ in width");
    let count = a.len();
    assert_eq!(out.len(), count + 1, "sub_checked_limbs: bad out width");

    let (lo, hi) = out.split_at_mut(count);

    if count == 1 {
        sub_checked_with_borrow(&mut lo[0], &mut hi[0], &a[0], &b[0], n_bits);
        return;
    }

    let mut borrow = raw::Tmp::new();
    sub_checked_with_borrow(&mut lo[0], &mut borrow, &a[0], &b[0], n_bits);

    for i in 1..count - 1 {
        let mut next = raw::Tmp::new();
        sub_3_checked_with_borrow(&mut lo[i], &mut next, &a[i], &b[i], &borrow, n_bits);
        borrow = next;
    }

    let last = count - 1;
    sub_3_checked_with_borrow(&mut lo[last], &mut hi[0], &a[last], &b[last], &borrow, n_bits);
}

/// `out = (a < b)` over raw limb slices, fully constrained.
///
/// The slice-level counterpart of [`Bn254FrBigint::lt`].
pub(crate) fn lt_checked_limbs(a: &[bn254fr_t], b: &[bn254fr_t], n_bits: u32) -> Bn254Fr {
    assert_eq!(a.len(), b.len(), "lt_checked_limbs: operands differ in width");
    let count = a.len();

    if count == 1 {
        let mut res = Bn254Fr::new();
        raw::lt_checked(res.handle_mut(), &a[0], &b[0], n_bits);
        return res;
    }

    let mut lt_bits = Vec::with_capacity(count);
    let mut eq_bits = Vec::with_capacity(count);
    for i in 0..count {
        let mut l = raw::Tmp::new();
        let mut e = raw::Tmp::new();
        raw::lt_checked(&mut l, &a[i], &b[i], n_bits);
        raw::eq_checked(&mut e, &a[i], &b[i]);
        lt_bits.push(l);
        eq_bits.push(e);
    }

    let mut ors: Vec<raw::Tmp> = (0..count - 1).map(|_| raw::Tmp::new()).collect();
    let mut ands: Vec<raw::Tmp> = (0..count - 1).map(|_| raw::Tmp::new()).collect();
    let mut eq_ands: Vec<raw::Tmp> = (0..count - 1).map(|_| raw::Tmp::new()).collect();

    raw::land_checked(&mut ands[count - 2], &eq_bits[count - 1], &lt_bits[count - 2]);
    raw::land_checked(
        &mut eq_ands[count - 2],
        &eq_bits[count - 1],
        &eq_bits[count - 2],
    );
    raw::lor_checked(&mut ors[count - 2], &lt_bits[count - 1], &ands[count - 2]);

    // Runs from count-3 down to 0; empty when count == 2.
    for i in (0..count.saturating_sub(2)).rev() {
        let mut a_i = raw::Tmp::new();
        raw::land_checked(&mut a_i, &eq_ands[i + 1], &lt_bits[i]);
        ands[i] = a_i;

        let mut e_i = raw::Tmp::new();
        raw::land_checked(&mut e_i, &eq_ands[i + 1], &eq_bits[i]);
        eq_ands[i] = e_i;

        let mut o_i = raw::Tmp::new();
        raw::lor_checked(&mut o_i, &ors[i + 1], &ands[i]);
        ors[i] = o_i;
    }

    let mut res = Bn254Fr::new();
    raw::copy(res.handle_mut(), &ors[0]);
    #[cfg(feature = "fault-injection")]
    crate::fault::corrupt_bigint_lt(res.handle_mut());
    raw::assert_equal(res.handle(), &ors[0]);
    res
}

/// `out = a * b`, carry-propagated and fully constrained, over raw limb slices.
///
/// The slice-level entry point. `Uint256` calls this directly rather than building a
/// [`Bn254FrBigint`]: the result is written straight into the caller's limbs, so there is no
/// intermediate object whose handles have to be moved out.
///
/// `out` must have `a.len() + b.len()` limbs.
pub(crate) fn mul_checked_limbs(
    out: &mut [bn254fr_t],
    a: &[bn254fr_t],
    b: &[bn254fr_t],
    bits: u32,
) {
    let no_carry_count = a.len() + b.len() - 1;
    assert_eq!(out.len(), no_carry_count + 1, "mul_checked_limbs: bad out width");

    let mut no_carry = vec![bn254fr_t::default(); no_carry_count];
    for h in &mut no_carry {
        raw::alloc(h);
    }

    bigint_mul_checked_no_carry(&mut no_carry, a, b);
    bigint_convert_to_proper_representation(out, &mut no_carry, bits);

    // Without this the limbs above are unconstrained witnesses.
    range_check(&no_carry, out, bits, a.len().min(b.len()));

    for h in &mut no_carry {
        raw::free(h);
    }
}

/// Compute product of two big integers without carry propagation.
///
/// `a` and `b` may have different limb counts; `out` must have
/// `a.len() + b.len() - 1` limbs.
fn bigint_mul_checked_no_carry(out: &mut [bn254fr_t], a: &[bn254fr_t], b: &[bn254fr_t]) {
    assert_eq!(out.len(), a.len() + b.len() - 1);

    unsafe {
        _bn254fr_bigint_mul_checked_no_carry(
            out.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            a.len() as u32,
            b.len() as u32,
        );
    }
}

/// Multiply two big integers with carry propagation, **without** constraints.
///
/// `out` must have `a.len() + b.len()` limbs.
fn bigint_mul(out: &mut [bn254fr_t], a: &[bn254fr_t], b: &[bn254fr_t], bits: u32) {
    assert_eq!(out.len(), a.len() + b.len());

    unsafe {
        _bn254fr_bigint_mul(
            out.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            a.len() as u32,
            b.len() as u32,
            bits,
        );
    }
}

/// Integer division of two big integers, **without** constraints. Writes quotient and
/// remainder. `q` must have `a.len()` limbs and `r` must have `b.len()`.
fn bigint_idiv(q: &mut [bn254fr_t], r: &mut [bn254fr_t], a: &[bn254fr_t], b: &[bn254fr_t], bits: u32) {

    unsafe {
        _bn254fr_bigint_idiv(
            q.as_mut_ptr(),
            r.as_mut_ptr(),
            a.as_ptr(),
            b.as_ptr(),
            a.len() as u32,
            b.len() as u32,
            bits,
        );
    }
}

/// Modular inverse of a big integer, **without** constraints.
fn bigint_invmod(out: &mut [bn254fr_t], a: &[bn254fr_t], m: &[bn254fr_t], bits: u32) {

    unsafe {
        _bn254fr_bigint_invmod(
            out.as_mut_ptr(),
            a.as_ptr(),
            m.as_ptr(),
            a.len() as u32,
            m.len() as u32,
            bits,
        );
    }
}

/// Convert a signed overflow-representation big integer to proper representation,
/// **without** constraints.
fn bigint_convert_to_proper_representation_signed(
    out: &mut [bn254fr_t],
    inp: &[bn254fr_t],
    bits: u32,
) {

    unsafe {
        _bn254fr_bigint_convert_to_proper_representation_signed(
            out.as_mut_ptr(),
            inp.as_ptr(),
            out.len() as u32,
            inp.len() as u32,
            bits,
        );
    }
}

/// Convert an unsigned overflow-representation big integer to proper representation,
/// **without** constraints.
fn bigint_convert_to_proper_representation_unsigned(
    out: &mut [bn254fr_t],
    inp: &[bn254fr_t],
    bits: u32,
) {

    unsafe {
        _bn254fr_bigint_convert_to_proper_representation_unsigned(
            out.as_mut_ptr(),
            inp.as_ptr(),
            out.len() as u32,
            inp.len() as u32,
            bits,
        );
    }
}

/// Convert a big integer to overflow representation with `overflow_bits` bits per limb.
fn bigint_convert_to_overflow_representation(
    out: &mut [bn254fr_t],
    inp: &[bn254fr_t],
    bits: u32,
    overflow_bits: u32,
) {

    unsafe {
        _bn254fr_bigint_convert_to_overflow_representation(
            out.as_mut_ptr(),
            inp.as_ptr(),
            out.len() as u32,
            inp.len() as u32,
            bits,
            overflow_bits,
        );
    }
}

/// Print a big integer to stdout.
fn bigint_print(x: &[bn254fr_t], n_bits: u32) {
    unsafe { _bn254fr_bigint_print(x.as_ptr(), x.len() as u32, n_bits) }
}

/// Convert a big integer to proper representation with carry propagation, **without**
/// constraints. Rewrites the handles of both `out` and `inp`.
///
/// `out` must have length `count + 1`, `inp` must have length `count`. The `+ 1` is where the
/// final carry lands, which is why this is a different host function from the
/// `..._proper_representation_{signed,unsigned}` pair, whose output is
/// [`proper_size`]-many limbs wide.
fn bigint_convert_to_proper_representation(out: &mut [bn254fr_t], inp: &mut [bn254fr_t], bits: u32) {
    let count = inp.len();
    assert_eq!(out.len(), count + 1);

    unsafe {
        _bn254fr_bigint_convert_to_proper_representation(
            out.as_mut_ptr(),
            inp.as_mut_ptr(),
            count as u32,
            bits,
        );
    }
}

#[link(wasm_import_module = "bn254fr")]
extern "C" {
    #[link_name = "bn254fr_bigint_mul_checked_no_carry"]
    fn _bn254fr_bigint_mul_checked_no_carry(
        out: *mut bn254fr_t,
        a: *const bn254fr_t,
        b: *const bn254fr_t,
        a_count: u32,
        b_count: u32,
    );

    #[link_name = "bn254fr_bigint_mul"]
    fn _bn254fr_bigint_mul(
        out: *mut bn254fr_t,
        a: *const bn254fr_t,
        b: *const bn254fr_t,
        a_count: u32,
        b_count: u32,
        bits: u32,
    );

    #[link_name = "bn254fr_bigint_idiv"]
    fn _bn254fr_bigint_idiv(
        q: *mut bn254fr_t,
        r: *mut bn254fr_t,
        a: *const bn254fr_t,
        b: *const bn254fr_t,
        a_count: u32,
        b_count: u32,
        bits: u32,
    );

    #[link_name = "bn254fr_bigint_invmod"]
    fn _bn254fr_bigint_invmod(
        out: *mut bn254fr_t,
        a: *const bn254fr_t,
        m: *const bn254fr_t,
        a_count: u32,
        m_count: u32,
        bits: u32,
    );

    #[link_name = "bn254fr_bigint_convert_to_proper_representation_signed"]
    fn _bn254fr_bigint_convert_to_proper_representation_signed(
        out: *mut bn254fr_t,
        inp: *const bn254fr_t,
        out_count: u32,
        in_count: u32,
        bits: u32,
    );

    #[link_name = "bn254fr_bigint_convert_to_proper_representation_unsigned"]
    fn _bn254fr_bigint_convert_to_proper_representation_unsigned(
        out: *mut bn254fr_t,
        inp: *const bn254fr_t,
        out_count: u32,
        in_count: u32,
        bits: u32,
    );

    #[link_name = "bn254fr_bigint_convert_to_overflow_representation"]
    fn _bn254fr_bigint_convert_to_overflow_representation(
        out: *mut bn254fr_t,
        inp: *const bn254fr_t,
        out_count: u32,
        in_count: u32,
        bits: u32,
        overflow_bits: u32,
    );

    #[link_name = "bn254fr_bigint_print"]
    fn _bn254fr_bigint_print(x: *const bn254fr_t, n_limbs: u32, n_bits: u32);

    #[link_name = "bn254fr_bigint_convert_to_proper_representation"]
    fn _bn254fr_bigint_convert_to_proper_representation(
        out: *mut bn254fr_t,
        inp: *mut bn254fr_t,
        count: u32,
        bits: u32,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bn254fr::bit_length;

    // These run natively: they exercise only the pure width arithmetic, which is exactly the
    // class of bug that stays invisible until a proof fails.

    #[test]
    fn bit_length_is_not_ceil_log2() {
        // They agree everywhere except the powers of two, where bit_length is one larger.
        // That difference is the whole reason both exist.
        for (n, bl, cl) in [
            (0u32, 0u32, 0u32),
            (1, 1, 0),
            (2, 2, 1),
            (3, 2, 2),
            (4, 3, 2),
            (5, 3, 3),
            (7, 3, 3),
            (8, 4, 3),
            (9, 4, 4),
            (255, 8, 8),
            (256, 9, 8),
        ] {
            assert_eq!(bit_length(n), bl, "bit_length({n})");
            assert_eq!(ceil_log2(n), cl, "ceil_log2({n})");
        }
    }

    #[test]
    fn proper_size_matches_cpp() {
        // Equal widths need no extra limbs.
        assert_eq!(proper_size(4, 64, 64), 4);
        // A 128-bit overflow limb needs one more limb per 64 bits.
        assert_eq!(proper_size(4, 64, 128), 6);
        assert_eq!(proper_size(4, 64, 250), 7);
    }

    #[test]
    fn mul_no_carry_width() {
        // 4x4 limbs of 64 bits: an output limb is a sum of at most 4 products, each
        // < 2^128, so it stays under 4 * 2^128 = 2^130. 64 + 64 + ceil_log2(4) = 130.
        // This was 131 until 1.7.0, when the term was bit_length(4) = 3.
        assert_eq!(mul_checked_no_carry_bits(4, 64, 4, 64), 130);
        // min() picks the shorter operand
        assert_eq!(mul_checked_no_carry_bits(8, 64, 4, 64), 130);
        // 5 products need 3 bits, and there bit_length and ceil_log2 agree.
        assert_eq!(mul_checked_no_carry_bits(5, 64, 5, 64), 131);
    }

    #[test]
    fn width_ceiling_is_250() {
        // The composite widths the field layer projects must stay under the ceiling.
        assert!(mul_checked_no_carry_bits(4, 64, 4, 64) <= MAX_BITS_COUNT);
        // Two chained multiplications would not.
        assert!(mul_checked_no_carry_bits(4, 131, 4, 131) > MAX_BITS_COUNT);
    }
}
