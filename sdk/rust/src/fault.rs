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

//! Deliberate corruption of host-oracle output, so negative tests can reach the assertions
//! that guard it.
//!
//! **Compiled only under `--features fault-injection`.** Never enable it outside
//! `tests_wasm/negative_*`; a build with this on has a documented way to make the prover lie.
//!
//! ## Why this exists
//!
//! [`AffineCurve::scalar_mul`](crate::ecc::curve::AffineCurve::scalar_mul) asks the host for
//! `[k]P` and for the rational reconstruction `k ≡ x/z`, then constrains both. Those
//! constraints are the entire soundness argument, and no *input* can exercise them: the honest
//! oracle always answers correctly, so the assertions are satisfied whether or not they are
//! there. That is why all of them showed up as mutation survivors.
//!
//! The oracle writes into ordinary mutable guest buffers, so the corruption itself was always
//! possible — what was missing was a place for a test to reach in. That is all this module is.
//!
//! ## Isolation
//!
//! A negative test is only meaningful if it trips **one** assertion; otherwise removing that
//! assertion leaves the proof failing for the other reason and the test never notices. The
//! faults below are chosen for that, and which ones actually achieve it is recorded in the
//! issue register (A18), measured rather than assumed.
//!
//! The subtle one is [`Fault::ScalarBeforeOracles`]. Corrupting `x` directly breaks step 5
//! *and* step 9, because with an honest `result = [k]P` those two say the same thing. Feeding
//! both oracles a `k'` instead keeps them self-consistent — `x ≡ z·k'` and `result = [k']P`, so
//! step 9 still passes — while step 5 compares against the real `k` and fails. That is exactly
//! the attack step 5 exists to stop: returning `[k']P` and claiming it is `[k]P`.

use core::sync::atomic::{AtomicU8, Ordering};

use crate::bn254fr::raw;

/// Which corruption `scalar_mul` should apply on its next call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Fault {
    /// Behave honestly.
    None = 0,

    /// Flip a bit in `k` before *both* oracle calls, so the decomposition and the result agree
    /// with each other but not with the `k` the circuit holds.
    ///
    /// Target: step 5, `x_signed == z_signed * k` (`curve.rs:171`).
    ScalarBeforeOracles = 1,

    /// Flip a bit in the oracle's `[k]P`, leaving the decomposition honest.
    ///
    /// Target: step 9, `[x]P + [z]Q == O` (`curve.rs:229`).
    ScalarMulResult = 2,

    /// Set the `x` sign flag to 2, which is neither 0 nor 1.
    ///
    /// Target: step 3, booleanity (`curve.rs:153`).
    SignFlagX = 3,

    /// Force `|x|` to zero.
    ///
    /// Target: step 4, `|x| != 0` (`curve.rs:157`).
    MagnitudeXZero = 4,

    // ---- uint256 -----------------------------------------------------------------------

    /// `r += 1` after `_uint512_idiv_normalized`, leaving `q` alone.
    ///
    /// Target: the multiply-back `q*b + r == a` in `divide_qr_normalized`.
    DivRemainderPlusOne = 10,

    /// `q -= 1, r += b` after `_uint512_idiv_normalized`.
    ///
    /// The multiply-back still holds -- `(q-1)*b + (r+b) == q*b + r` -- so only `r < b` can
    /// notice. This is the textbook non-uniqueness attack on division, and the only reason
    /// `r < b` is a soundness constraint rather than a tidiness one.
    ///
    /// Target: `r < b` in `divide_qr_normalized`.
    DivNonUnique = 11,

    /// `result += 1` after `_uint256_invmod`.
    ///
    /// Target: `result * a === 1 (mod m)` in `uint256::invmod`.
    Uint256InvmodResult = 12,

    /// Skew a limb between the `copy` and the `assert_equal` in `Uint256::set_words`.
    ///
    /// This class of assertion cannot be reached by ANY input, and not by corrupting an oracle
    /// either: the copy immediately before it makes the two sides equal by construction. It
    /// binds a value a malicious prover would otherwise be free to choose, so the only way to
    /// exercise it is to be that prover -- which is what this fault does.
    ///
    /// Target: `set_words`'s per-limb binding (`uint256.rs:350`).
    SetWordsSkew = 13,

    /// The same, for `Uint256::from_bits`.
    ///
    /// Target: `from_bits`'s per-limb binding (`uint256.rs:436`).
    FromBitsSkew = 14,

    // ---- bn254fr_bigint ----------------------------------------------------------------

    /// `q.limbs[0] += 1` after `idiv_unchecked` inside `Bn254FrBigint::idiv`.
    ///
    /// Target: the multiply-back `q*b + r == a` in `idiv`.
    BigintIdivQuotient = 20,

    /// `out.limbs[0] -= 1` after `idiv_unchecked` inside `Bn254FrBigint::rem`.
    ///
    /// Target: `q*m + out === a` in `rem`.
    BigintRemOut = 21,

    /// Zeroes the whole result after `invmod_unchecked` -- i.e. claims `a^-1 == 0`.
    ///
    /// Target: `a * a^-1 == 1 (mod m)` in `Bn254FrBigint::invmod`.
    BigintInvmodResult = 22,

    /// `q -= 1, r = b` in `Bn254FrBigint::idiv`, for an `a` that is an exact multiple of `b`.
    ///
    /// With `r == 0` honestly, `(q-1)*b + b == q*b == a`, so the multiply-back is satisfied and
    /// `r < b` is the only assertion that can object. Setting `r` to `b` outright avoids doing
    /// multi-limb arithmetic inside the fault, which would risk changing limb counts and
    /// tripping something else.
    ///
    /// Target: `r < b` (`bn254fr_bigint.rs:874`).
    BigintIdivNonUnique = 23,

    /// The same shift, one function over: `q -= 1, out = m` in `Bn254FrBigint::rem`.
    ///
    /// Target: `out < m` (`bn254fr_bigint.rs:899`).
    BigintRemNonUnique = 24,

    // The four remaining copy/assert_equal pairs in bn254fr_bigint. Same shape as
    // [`Fault::SetWordsSkew`]: skew the destination between the copy and the assertion, since
    // the copy makes the two sides equal by construction and no input can separate them.
    /// Target: `from_limbs_checked`'s per-limb binding (`bn254fr_bigint.rs:279`).
    BigintFromLimbsSkew = 25,
    /// Target: `set`'s per-limb binding (`bn254fr_bigint.rs:339`).
    BigintSetSkew = 26,
    /// Target: `add_no_carry`'s surplus-limb binding (`bn254fr_bigint.rs:700`).
    BigintAddSurplusSkew = 27,
    /// Target: `sub_no_carry`'s surplus-limb binding (`bn254fr_bigint.rs:776`).
    BigintSubSurplusSkew = 28,

    /// Target: `lt`'s result binding (`bn254fr_bigint.rs:498`). Another copy/assert pair.
    BigintLtSkew = 29,

    /// Target: `add_checked`'s carry-out binding (`bn254fr_bigint.rs:752`). Copy/assert again:
    /// the final carry becomes the top limb, and this is what stops a prover picking its own.
    BigintAddCarrySkew = 30,

    /// Skews the TOP limb of the host's proper representation inside `mul`, before
    /// `range_check` sees it.
    ///
    /// Not a copy/assert pair. `range_check` bit-checks limbs `0..count` but leaves `out[count]`
    /// -- the final carry limb -- to be pinned solely by the equality against the running carry
    /// it recomputes. Skewing that limb is the only thing that assertion can see.
    ///
    /// Target: `range_check`'s carry binding (`bn254fr_bigint.rs:129`).
    BigintProperTopSkew = 31,

    /// Skews `tmp` between the copy and the assertion in `range_check_signed`.
    ///
    /// That branch runs only when the output is WIDER than the input, so the test has to pick
    /// operands whose proper representation grows a limb.
    ///
    /// Target: `range_check_signed`'s pass-through binding (`bn254fr_bigint.rs:166`).
    BigintSignedCopySkew = 32,

    // ---- ff/ ---------------------------------------------------------------------------

    /// Skews a limb between the `set_u64` and the `assert_equal_u64` in `import_u32`'s
    /// full-limb loop. `set_u64` is the UNCHECKED setter, so the assertion is the only thing
    /// binding the imported limb to the literal it came from.
    ///
    /// Target: `ff/storage.rs:530`.
    FfImportU64Skew = 33,

    /// The same for the odd trailing 32-bit limb. That branch runs only for an ODD number of
    /// input words, so the two tests exercise disjoint paths.
    ///
    /// Target: `ff/storage.rs:537`.
    FfImportU32Skew = 34,

    /// `q -= 1` after `idiv_unchecked` in `assert_equal_zero_mod`, so `d = x - q*m` becomes `m`
    /// instead of zero.
    ///
    /// Only the `d_proper == 0` loop can see this: `r` comes from the same division and is left
    /// alone, so the second loop still passes.
    ///
    /// Target: `ff/storage.rs`'s `d_proper` zero check.
    FfZeroModSkew = 35,

    /// Makes `b_pad` -- the fifth limb the divisor is padded with -- nonzero.
    ///
    /// Isolating this needs the right INPUT, not a cleverer fault: pick `a < b` so the quotient
    /// is zero. Then `mul_q` is all zeros and `q * b` is zero whatever `b_pad` holds, so the
    /// multiply-back cannot see the pad at all, and `r < b` holds because `r == a`. Only the
    /// pad's own zero-assertion is left to object.
    ///
    /// Target: `uint256.rs:91`.
    DivBPadSkew = 36,

    /// Replaces the oracle's inverse with `res * (1 + 2^64) mod m`, so the product verifies as
    /// `1 + 2^64` instead of `1`.
    ///
    /// Limb 0 is then still 1 -- satisfying the `limbs[0] == 1` check ABOVE the target -- while
    /// limb 1 is 1 rather than 0. That is the ONLY way to reach the `rest == 0` loop:
    /// [`Fault::BigintInvmodResult`] deliberately makes the product zero, which satisfies this
    /// loop vacuously.
    ///
    /// This is A23's attack made concrete. Before that fix the higher limbs were compared
    /// against a free witness, so a prover could pass `zero = k` and have
    /// `res * a mod m == 1 + k*2^64` accepted as an inverse.
    ///
    /// Target: `bn254fr_bigint.rs:966`.
    BigintInvmodRestSkew = 37,

}

static ACTIVE: AtomicU8 = AtomicU8::new(0);

/// Arms a fault for every subsequent `scalar_mul` on this program run.
pub fn arm(fault: Fault) {
    ACTIVE.store(fault as u8, Ordering::Relaxed);
}

fn armed(fault: Fault) -> bool {
    ACTIVE.load(Ordering::Relaxed) == fault as u8
}

/// Applied to the little-endian scalar before either oracle sees it.
pub(crate) fn corrupt_scalar(k_bytes: &mut [u8]) {
    if armed(Fault::ScalarBeforeOracles) {
        // The low bit, so k' stays a valid nonzero scalar for any k > 1.
        k_bytes[0] ^= 1;
    }
}

/// Applied to the oracle's affine `x || y` result.
pub(crate) fn corrupt_point(out_bytes: &mut [u8]) {
    if armed(Fault::ScalarMulResult) {
        out_bytes[0] ^= 1;
    }
}

/// Applied to the oracle's rational reconstruction.
pub(crate) fn corrupt_decomposition(x_abs: &mut [u8], x_positive: &mut i32) {
    if armed(Fault::SignFlagX) {
        *x_positive = 2;
    }
    if armed(Fault::MagnitudeXZero) {
        for b in x_abs.iter_mut() {
            *b = 0;
        }
    }
}

// ---- uint256 -------------------------------------------------------------------------------

/// Applied to `_uint512_idiv_normalized`'s output, before anything constrains it.
///
/// `divisor` is passed so [`Fault::DivNonUnique`] can shift a whole `b` from the quotient into
/// the remainder, which is the only perturbation the multiply-back cannot see.
pub(crate) fn corrupt_div_qr(
    q_low: &mut crate::uint256::Uint256,
    r: &mut crate::uint256::Uint256,
    divisor: &crate::uint256::Uint256,
) {
    use crate::uint256::{add_cc, sub_cc, Uint256};

    if armed(Fault::DivRemainderPlusOne) {
        *r = add_cc(r, &Uint256::from_u64(1)).val;
    }
    if armed(Fault::DivNonUnique) {
        *q_low = sub_cc(q_low, &Uint256::from_u64(1)).val;
        *r = add_cc(r, divisor).val;
    }
}

/// Applied to the divisor's zero pad in `divide_qr_normalized`.
pub(crate) fn corrupt_div_b_pad(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::DivBPadSkew) {
        skew(h);
    }
}

/// Applied to `_uint256_invmod`'s output.
pub(crate) fn corrupt_uint256_invmod(result: &mut crate::uint256::Uint256) {
    use crate::uint256::{add_cc, Uint256};

    if armed(Fault::Uint256InvmodResult) {
        *result = add_cc(result, &Uint256::from_u64(1)).val;
    }
}

/// `h += 1`, unconstrained. Used to break a copy/assert_equal pair from the inside.
fn skew(h: &mut crate::bn254fr::bn254fr_t) {
    let one = raw::Tmp::from_u32(1);
    let mut sum = raw::Tmp::new();
    raw::addmod(&mut sum, h, &one);
    raw::copy(h, &sum);
}

/// Applied between the copy and the assert_equal in `Uint256::set_words`.
pub(crate) fn corrupt_set_words(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::SetWordsSkew) {
        skew(limb);
    }
}

/// Applied between the copy and the assert_equal in `Uint256::from_bits`.
pub(crate) fn corrupt_from_bits(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::FromBitsSkew) {
        skew(limb);
    }
}

// ---- bn254fr_bigint ------------------------------------------------------------------------

/// `limbs[0] += 1`, in place, with no carry propagation.
///
/// Carry does not matter here: these faults only need the value to be wrong, and the test
/// inputs are chosen so limb 0 is nowhere near its range-check ceiling. If it were, the limb's
/// own `check_bits` would fire and the test would be attributing the failure to the wrong line.
fn bump_low_limb(x: &mut crate::bn254fr_bigint::Bn254FrBigint) {
    let one = raw::Tmp::from_u32(1);
    let mut sum = raw::Tmp::new();
    // `addmod`, NOT `addmod_checked`. The checked form emits `sum == limbs[0] + 1`, and the
    // copy below then changes `limbs[0]`'s value out from under that constraint -- so the
    // proof would fail on the fault's own machinery no matter what the SDK asserts, and every
    // test using it would pass for the wrong reason. Measured: with `addmod_checked` here, all
    // three bigint suites still failed to prove after their target assertion was deleted.
    //
    // Unchecked is safe precisely because the oracle's output is not yet bound by anything;
    // that is the whole reason these assertions exist.
    raw::addmod(&mut sum, &x.limbs()[0], &one);
    raw::copy(&mut x.limbs_mut()[0], &sum);
}

/// `limbs[0] -= 1`, in place. Used where `+1` would push an intermediate NEGATIVE and trip a
/// range check inside `to_proper` before the assertion under test could fire.
fn drop_low_limb(x: &mut crate::bn254fr_bigint::Bn254FrBigint) {
    let one = raw::Tmp::from_u32(1);
    let mut diff = raw::Tmp::new();
    raw::submod(&mut diff, &x.limbs()[0], &one);
    raw::copy(&mut x.limbs_mut()[0], &diff);
}

/// Sets every limb to zero, unconstrained.
fn zero_all_limbs(x: &mut crate::bn254fr_bigint::Bn254FrBigint) {
    let zero = raw::Tmp::from_u32(0);
    for limb in x.limbs_mut().iter_mut() {
        raw::copy(limb, &zero);
    }
}

/// Copies `src`'s limbs over `dst`'s, unconstrained. Both must have the same limb count --
/// true wherever this is used, since `idiv_unchecked` sizes its remainder from the divisor.
fn overwrite_limbs(
    dst: &mut crate::bn254fr_bigint::Bn254FrBigint,
    src: &crate::bn254fr_bigint::Bn254FrBigint,
) {
    for i in 0..dst.limbs_count().min(src.limbs_count()) {
        let v = src.limbs()[i];
        raw::copy(&mut dst.limbs_mut()[i], &v);
    }
}

/// Applied to `idiv_unchecked`'s output inside `Bn254FrBigint::idiv`.
pub(crate) fn corrupt_bigint_idiv(
    q: &mut crate::bn254fr_bigint::Bn254FrBigint,
    r: &mut crate::bn254fr_bigint::Bn254FrBigint,
    b: &crate::bn254fr_bigint::Bn254FrBigint,
) {
    if armed(Fault::BigintIdivQuotient) {
        bump_low_limb(q);
    }
    if armed(Fault::BigintIdivNonUnique) {
        drop_low_limb(q);
        overwrite_limbs(r, b);
    }
}

/// Applied to `idiv_unchecked`'s output inside `Bn254FrBigint::rem`.
pub(crate) fn corrupt_bigint_rem(
    q: &mut crate::bn254fr_bigint::Bn254FrBigint,
    out: &mut crate::bn254fr_bigint::Bn254FrBigint,
    m: &crate::bn254fr_bigint::Bn254FrBigint,
) {
    if armed(Fault::BigintRemNonUnique) {
        drop_low_limb(q);
        overwrite_limbs(out, m);
    }
    if armed(Fault::BigintRemOut) {
        // DECREMENT, not increment. `rem` verifies `a - (q*m + out) == 0`; bumping `out` up
        // makes that difference negative, and `to_proper` on a negative value trips its own
        // range check before the zero-assertion is reached. Measured: with `+1` here, deleting
        // the target assertion still left the suite failing.
        drop_low_limb(out);
    }
}

/// Applied to `invmod_unchecked`'s result.
pub(crate) fn corrupt_bigint_invmod(
    res: &mut crate::bn254fr_bigint::Bn254FrBigint,
    m: &crate::bn254fr_bigint::Bn254FrBigint,
) {
    if armed(Fault::BigintInvmodRestSkew) {
        // res' = res * (1 + 2^64) mod m, so res' * a === 1 + 2^64 (mod m).
        let mut k = crate::bn254fr_bigint::Bn254FrBigint::with_limbs(2);
        // with_limbs only ALLOCATES -- the limbs are whatever the recycled mpz held -- so both
        // must be set explicitly.
        raw::set_u32(&mut k.limbs_mut()[0], 1);
        raw::set_u32(&mut k.limbs_mut()[1], 1);
        let t = crate::bn254fr_bigint::Bn254FrBigint::mul_unchecked(res, &k);
        *res = crate::bn254fr_bigint::Bn254FrBigint::rem(&t, m);
    }
    if armed(Fault::BigintInvmodResult) {
        // Claim ZERO is the inverse. `a * 0 mod m == 0`, so limb 0 is 0 (not 1) while every
        // higher limb is legitimately 0 -- which is what isolates the `limbs[0] == 1` check
        // from the `rest == 0` loop beneath it. Bumping by one instead leaves the product a
        // full-width value, tripping both.
        zero_all_limbs(res);
    }
}

/// The four copy/assert_equal pairs in bn254fr_bigint. One entry point each, because a single
/// shared fault would fire at whichever site ran first and the test could not say which
/// assertion it had exercised.
pub(crate) fn corrupt_bigint_from_limbs(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintFromLimbsSkew) {
        skew(limb);
    }
}

pub(crate) fn corrupt_bigint_set(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintSetSkew) {
        skew(limb);
    }
}

pub(crate) fn corrupt_bigint_add_surplus(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintAddSurplusSkew) {
        skew(limb);
    }
}

pub(crate) fn corrupt_bigint_sub_surplus(limb: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintSubSurplusSkew) {
        skew(limb);
    }
}

/// The last four bindings in bn254fr_bigint. Separate arms for the same reason as the others:
/// a shared fault could not say which assertion a failure belonged to.
pub(crate) fn corrupt_bigint_lt(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintLtSkew) {
        skew(h);
    }
}

pub(crate) fn corrupt_bigint_add_carry(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintAddCarrySkew) {
        skew(h);
    }
}

pub(crate) fn corrupt_bigint_proper_top(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintProperTopSkew) {
        skew(h);
    }
}

pub(crate) fn corrupt_bigint_signed_copy(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::BigintSignedCopySkew) {
        skew(h);
    }
}

/// The ff/ layer. `import_u32` binds each limb to a literal via an UNCHECKED setter, so the
/// assertion is all that stands between the import and a freely chosen witness.
pub(crate) fn corrupt_ff_import_u64(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::FfImportU64Skew) {
        skew(h);
    }
}

pub(crate) fn corrupt_ff_import_u32(h: &mut crate::bn254fr::bn254fr_t) {
    if armed(Fault::FfImportU32Skew) {
        skew(h);
    }
}

/// Applied to `assert_equal_zero_mod`'s quotient.
pub(crate) fn corrupt_ff_zero_mod(q: &mut crate::bn254fr_bigint::Bn254FrBigint) {
    if armed(Fault::FfZeroModSkew) {
        drop_low_limb(q);
    }
}
