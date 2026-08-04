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

//! 256-bit Unsigned Integer Operations for Ligetron
//!
//! This module provides 256-bit unsigned integer arithmetic with automatic
//! constraint generation for zero-knowledge proofs. A Uint256 is composed
//! of 4 64-bit limbs stored as BN254 field elements.

use crate::bn254fr::{assert_equal_u32, bn254fr_t, raw, Bn254Fr, ORDER_BIG, ORDER_LITTLE};
use crate::bn254fr_bigint::Bn254FrBigint;

/// Number of 64-bit limbs in a Uint256
pub const UINT256_NLIMBS: usize = 4;

/// Result of addition/subtraction with carry/borrow.
pub struct Uint256Cc {
    pub val: Uint256,
    pub carry: Bn254Fr,
}

/// 512-bit wide result (used for multiplication).
pub struct Uint256Wide {
    pub lo: Uint256,
    pub hi: Uint256,
}

impl Uint256Wide {
    /// Perform 512-bit division by normalized divisor, adds constraints.
    /// Returns (quotient_low, quotient_high_limb, remainder).
    ///
    /// The host computes the quotient and remainder out of circuit, then this proves the
    /// answer: every output limb is range-checked, `q * b + r == a` is asserted limb by limb
    /// over the full 512-bit width, and `r < b` is asserted. Without the multiply-back the
    /// oracle's output would be a free witness.
    ///
    /// **`divisor`'s most significant limb must be nonzero** -- that is, `divisor >= 2^192`.
    /// The quotient is sized at 256 + 64 bits, and `2^512 / 2^192 = 2^320` is exactly that
    /// width, so the bound is tight: `2^192` divides fine and `2^192 - 1` does not. Note this
    /// is the limb condition, not the stronger top-bit-set sense of "normalized".
    ///
    /// Violating it is **not** silent: `q_high` fails its 64-bit range check and the proof is
    /// rejected. There is deliberately no runtime assert, because branching on the divisor
    /// would make the circuit's shape depend on a value that may be private, and the verifier
    /// does not have it.
    pub fn divide_qr_normalized(&self, divisor: &Uint256) -> (Uint256, Bn254Fr, Uint256) {
        const W: usize = UINT256_NLIMBS + 1;

        let mut q_low = Uint256::new();
        let mut q_high = Bn254Fr::new();
        let mut r = Uint256::new();

        unsafe {
            _uint512_idiv_normalized(
                &mut q_low,
                q_high.handle_mut(),
                &mut r,
                &self.lo,
                &self.hi,
                divisor,
            );
        }
        // Test-only seam; absent without `--features fault-injection`. See `crate::fault`.
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_div_qr(&mut q_low, &mut r, divisor);

        // Range check outputs.
        for i in 0..UINT256_NLIMBS {
            raw::check_bits(&q_low.limbs[i], LIMB_BITS as u32);
            raw::check_bits(&r.limbs[i], LIMB_BITS as u32);
        }
        raw::check_bits(q_high.handle(), LIMB_BITS as u32);

        // q is 256 + 64 bits wide, so it needs a fifth limb; b is padded to match. The pads are
        // set and constrained to zero: a fresh handle is *not* initialised, and an unconstrained
        // one could be chosen by the prover.
        #[allow(unused_mut)]
        let mut b_pad = Bn254Fr::from_u32(0);
        #[cfg(feature = "fault-injection")]
        crate::fault::corrupt_div_b_pad(b_pad.handle_mut());
        assert_equal_u32(&b_pad, 0);
        let mut mul_q = [bn254fr_t::default(); W];
        let mut mul_b = [bn254fr_t::default(); W];
        mul_q[..UINT256_NLIMBS].copy_from_slice(&q_low.limbs);
        mul_q[UINT256_NLIMBS] = *q_high.handle();
        mul_b[..UINT256_NLIMBS].copy_from_slice(&divisor.limbs);
        mul_b[UINT256_NLIMBS] = *b_pad.handle();

        let mut mul_out = [bn254fr_t::default(); 2 * W];
        for h in &mut mul_out {
            raw::alloc(h);
        }
        crate::bn254fr_bigint::mul_checked_limbs(&mut mul_out, &mul_q, &mul_b, LIMB_BITS as u32);

        // q * b + r, with r zero-extended to the product width.
        let r_pad: Vec<Bn254Fr> = (0..2 * W - UINT256_NLIMBS)
            .map(|_| {
                let z = Bn254Fr::from_u32(0);
                assert_equal_u32(&z, 0);
                z
            })
            .collect();
        let mut add_r = [bn254fr_t::default(); 2 * W];
        add_r[..UINT256_NLIMBS].copy_from_slice(&r.limbs);
        for (dst, src) in add_r[UINT256_NLIMBS..].iter_mut().zip(r_pad.iter()) {
            *dst = *src.handle();
        }

        let mut add_out = [bn254fr_t::default(); 2 * W + 1];
        for h in &mut add_out {
            raw::alloc(h);
        }
        crate::bn254fr_bigint::add_checked_limbs(
            &mut add_out,
            &mul_out,
            &add_r,
            LIMB_BITS as u32,
        );

        // q * b + r === a, over the whole 512-bit width, with the limbs above it zero.
        for i in 0..UINT256_NLIMBS {
            raw::assert_equal(&add_out[i], &self.lo.limbs[i]);
            raw::assert_equal(&add_out[UINT256_NLIMBS + i], &self.hi.limbs[i]);
        }
        // Limbs 8 and 9 must vanish. Limb 10 is the final carry, which the preceding assertions
        // already determine, so it is deliberately left free.
        for limb in add_out.iter().take(2 * W).skip(2 * UINT256_NLIMBS) {
            raw::assert_equal_u32(limb, 0);
        }

        // r < b, so the pair is the unique quotient/remainder rather than any factorisation.
        let lt = crate::bn254fr_bigint::lt_checked_limbs(
            &r.limbs,
            &divisor.limbs,
            LIMB_BITS as u32,
        );
        assert_equal_u32(&lt, 1);

        for h in &mut mul_out {
            raw::free(h);
        }
        for h in &mut add_out {
            raw::free(h);
        }

        (q_low, q_high, r)
    }

    /// Perform 512-bit mod operation, adds constraints.
    pub fn modulo(&self, m: &Uint256) -> Uint256 {
        let (_, _, r) = self.divide_qr_normalized(m);
        r
    }
}


/// A 256-bit unsigned integer: four contiguous `bn254fr_t` handles.
///
/// Layout-identical to the host's `uint256_t` — four contiguous `bn254fr_t` — which is what
/// lets `&self` be handed straight to the `uint256_*` host functions. Storing `Bn254Fr` would
/// give a
/// 16-byte stride the C API cannot read, forcing the handle marshalling that used to leak host
/// pointers into the proof. See [`crate::bn254fr::raw`].
#[repr(C)]
pub struct Uint256 {
    limbs: [bn254fr_t; UINT256_NLIMBS],
}

impl Drop for Uint256 {
    fn drop(&mut self) {
        for limb in &mut self.limbs {
            raw::free(limb);
        }
    }
}

impl Clone for Uint256 {
    fn clone(&self) -> Self {
        let mut out = Uint256::new();
        out.copy_checked(&self);
        out
    }
}

impl Default for Uint256 {
    fn default() -> Self {
        let mut out = Uint256 {
            limbs: [bn254fr_t::default(); UINT256_NLIMBS],
        };
        for limb in &mut out.limbs {
            raw::alloc(limb);
        }
        out
    }
}

impl Uint256 {
    /// Create a new uninitialized Uint256 (all limbs set to zero).
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy value from another Uint256 with constraints.
    pub fn copy_checked(&mut self, other: &Uint256) {
        for i in 0..UINT256_NLIMBS {
            raw::copy(&mut self.limbs[i], &other.limbs[i]);
            raw::assert_equal(&self.limbs[i], &other.limbs[i]);
        }
    }

    /// Get a reference to a limb
    #[inline(always)]
    /// All four limbs as a contiguous handle slice.
    pub(crate) fn limbs_all(&self) -> &[bn254fr_t] {
        &self.limbs
    }

    pub(crate) fn limb(&self, i: usize) -> &bn254fr_t {
        &self.limbs[i]
    }

    /// Get a mutable reference to a limb
    #[inline(always)]
    pub(crate) fn limb_mut(&mut self, i: usize) -> &mut bn254fr_t {
        &mut self.limbs[i]
    }

    /// Set value from little-endian bytes (unchecked - no constraints added).
    pub fn set_bytes_little_unchecked(&mut self, bytes: &[u8]) {
        unsafe {
            _uint256_set_bytes_little(self, bytes.as_ptr(), bytes.len() as u32);
        }
    }

    /// Set value from big-endian bytes (unchecked - no constraints added).
    pub fn set_bytes_big_unchecked(&mut self, bytes: &[u8]) {
        unsafe {
            _uint256_set_bytes_big(self, bytes.as_ptr(), bytes.len() as u32);
        }
    }

    /// Set value from string representation (unchecked).
    pub fn set_str(&mut self, s: &str, base: u32) {
        // Create null-terminated C string
        let c_str = std::ffi::CString::new(s).expect("CString::new failed");
        unsafe {
            _uint256_set_str(self, c_str.as_ptr(), base);
        }
    }

    /// Print the value (for debugging).
    pub fn print(&self) {
        unsafe {
            _uint256_print(self);
        }
    }

    /// Create a Uint256 from a u64 value.
    pub fn from_u64(val: u64) -> Self {
        let mut out = Self::new();
        out.set_u64(val);
        out
    }

    /// Create a Uint256 from a string.
    pub fn from_str(s: &str, base: u32) -> Self {
        let mut out = Self::new();
        out.set_str(s, base);
        out
    }

    /// Set value from u64.
    pub fn set_u64(&mut self, val: u64) {
        raw::set_u64(&mut self.limbs[0], val);
        for i in 1..UINT256_NLIMBS {
            raw::set_u64(&mut self.limbs[i], 0);
        }
    }

    /// Set value from u32.
    pub fn set_u32(&mut self, val: u32) {
        raw::set_u32(&mut self.limbs[0], val);
        for i in 1..UINT256_NLIMBS {
            raw::set_u64(&mut self.limbs[i], 0);
        }
    }

    /// Set value from a Bn254Fr field element.
    /// The field element must fit in 64 bits. Sets limb 0 and zeros others.
    pub fn set_bn254(&mut self, bn254: &Bn254Fr) {
        raw::copy(&mut self.limbs[0], bn254.handle());
        raw::assert_equal(&self.limbs[0], bn254.handle());
        // Range check to ensure it fits in 64 bits
        raw::check_bits(&self.limbs[0], 64u32);
        for i in 1..UINT256_NLIMBS {
            raw::set_u64(&mut self.limbs[i], 0);
        }
    }

    /// Get value as u64 with constraints.
    /// Adds constraints asserting higher limbs are zero.
    pub fn get_u64(&self) -> u64 {
        // Assert the higher limbs are zero. Constrain against the constant directly: comparing
        // against a fresh `Bn254Fr` would be worthless twice over — `Bn254Fr::new()` does not
        // initialise the value (the backend recycles the underlying `mpz`), and the handle is
        // itself unconstrained, so a prover could satisfy the assertion by choosing it.
        for i in 1..UINT256_NLIMBS {
            raw::assert_equal_u32(&self.limbs[i], 0);
        }
        // Range check limb 0 and return value
        raw::check_bits(&self.limbs[0], 64u32);
        raw::get_u64(&self.limbs[0])
    }

    /// Get value as u64 without constraints (unchecked).
    pub fn get_u64_unchecked(&self) -> u64 {
        raw::get_u64(&self.limbs[0])
    }

    /// Set value from little-endian bytes with constraints.
    pub fn set_bytes_little(&mut self, bytes: &[u8]) {
        // Use unchecked version first
        self.set_bytes_little_unchecked(bytes);
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            raw::check_bits(&self.limbs[i], 64u32);
        }
    }

    /// Set value from big-endian bytes with constraints.
    pub fn set_bytes_big(&mut self, bytes: &[u8]) {
        // Use unchecked version first
        self.set_bytes_big_unchecked(bytes);
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            raw::check_bits(&self.limbs[i], 64u32);
        }
    }

    /// Set limbs from array of Bn254Fr values with constraints.
    pub fn set_words(&mut self, words: &[Bn254Fr; UINT256_NLIMBS]) {
        for i in 0..UINT256_NLIMBS {
            raw::copy(&mut self.limbs[i], words[i].handle());
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_set_words(&mut self.limbs[i]);
            raw::assert_equal(&self.limbs[i], words[i].handle());
            // Range check each limb to 64 bits
            raw::check_bits(&self.limbs[i], 64u32);
        }
    }

    /// Set limbs from an array of `Bn254Fr` values, adding only equality constraints.
    ///
    /// Unlike [`Uint256::set_words`] this does **not** range-check each limb.
    /// The field layer calls this on every reduction,
    /// so the 256 extra bit constraints `set_words` would add are not free.
    pub fn set_words_checked(&mut self, words: &[Bn254Fr; UINT256_NLIMBS]) {
        for i in 0..UINT256_NLIMBS {
            raw::copy(&mut self.limbs[i], words[i].handle());
            raw::assert_equal(&self.limbs[i], words[i].handle());
        }
    }

    /// Get limbs as array of Bn254Fr values with constraints.
    pub fn get_words(&self) -> [Bn254Fr; UINT256_NLIMBS] {
        let mut words = [
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
        ];
        for i in 0..UINT256_NLIMBS {
            raw::copy(words[i].handle_mut(), &self.limbs[i]);
            raw::assert_equal(words[i].handle(), &self.limbs[i]);
        }
        words
    }

    /// View this value as a [`Bn254FrBigint`] in proper representation, with constraints.
    ///
    /// The bridge between the two bigint types: `Uint256` is fixed at four 64-bit limbs,
    /// `Bn254FrBigint` is variable-width, and this is how the former reaches the latter's
    /// arithmetic without either side handling limbs directly.
    pub fn to_bigint(&self) -> Bn254FrBigint {
        Bn254FrBigint::from_limbs_checked(&self.limbs, LIMB_BITS as u32, true)
    }

    /// Convert to little-endian bytes (32 bytes), with constraints.
    ///
    /// Each limb goes out through [`crate::bn254fr::raw::to_bytes_checked`], which
    /// re-materialises every byte as a witness and binds the bytes back to the limb.
    pub fn to_bytes_little(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..UINT256_NLIMBS {
            raw::to_bytes_checked(&mut bytes[i * 8..(i + 1) * 8], &self.limbs[i], ORDER_LITTLE);
        }
        bytes
    }

    /// Convert to big-endian bytes (32 bytes), with constraints.
    pub fn to_bytes_big(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..UINT256_NLIMBS {
            raw::to_bytes_checked(
                &mut bytes[i * 8..(i + 1) * 8],
                &self.limbs[UINT256_NLIMBS - 1 - i],
                ORDER_BIG,
            );
        }
        bytes
    }

    /// Decompose uint256 into 256 bits with constraints.
    pub fn to_bits(&self) -> Vec<Bn254Fr> {
        let mut all_bits = Vec::with_capacity(256);
        for i in 0..UINT256_NLIMBS {
            let limb_bits = crate::bn254fr::bits_of(&self.limbs[i], 64);
            all_bits.extend(limb_bits);
        }
        all_bits
    }

    /// Compose uint256 from 256 bits with constraints.
    pub fn from_bits(bits: &[Bn254Fr]) -> Self {
        assert!(bits.len() == 256, "from_bits requires exactly 256 bits");
        let mut result = Uint256::new();
        for i in 0..UINT256_NLIMBS {
            let start = i * 64;
            let end = start + 64;
            let v = Bn254Fr::from_bits_checked(&bits[start..end]);
            raw::copy(&mut result.limbs[i], v.handle());
            #[cfg(feature = "fault-injection")]
            crate::fault::corrupt_from_bits(&mut result.limbs[i]);
            raw::assert_equal(&result.limbs[i], v.handle());
        }
        result
    }
}

// ============= Host Function Declarations =============
#[link(wasm_import_module = "uint256")]
extern "C" {
    #[link_name = "uint256_set_bytes_little"]
    fn _uint256_set_bytes_little(out: *mut Uint256, bytes: *const u8, len: u32);

    #[link_name = "uint256_set_bytes_big"]
    fn _uint256_set_bytes_big(out: *mut Uint256, bytes: *const u8, len: u32);

    #[link_name = "uint256_set_str"]
    fn _uint256_set_str(out: *mut Uint256, s: *const i8, base: u32);

    #[link_name = "uint256_print"]
    fn _uint256_print(a: *const Uint256);

    #[link_name = "uint512_idiv_normalized"]
    fn _uint512_idiv_normalized(
        q_low: *mut Uint256,
        q_high: *mut bn254fr_t,
        r: *mut Uint256,
        a_low: *const Uint256,
        a_high: *const Uint256,
        b: *const Uint256,
    );

    #[link_name = "uint256_invmod"]
    fn _uint256_invmod(out: *mut Uint256, a: *const Uint256, m: *const Uint256);
}

// ============= Comparison Operations =============

/// Compare two Uint256 values for equality.
/// Returns 1 if equal, 0 otherwise. Adds constraints.
pub fn eq(x: &Uint256, y: &Uint256) -> Bn254Fr {
    // Compare all limbs and AND the results
    let mut eq0 = Bn254Fr::new();
    let mut eq1 = Bn254Fr::new();
    let mut eq2 = Bn254Fr::new();
    let mut eq3 = Bn254Fr::new();

    raw::eq_checked(eq0.handle_mut(), x.limb(0), y.limb(0));
    raw::eq_checked(eq1.handle_mut(), x.limb(1), y.limb(1));
    raw::eq_checked(eq2.handle_mut(), x.limb(2), y.limb(2));
    raw::eq_checked(eq3.handle_mut(), x.limb(3), y.limb(3));

    // AND all equality results: result = eq0 * eq1 * eq2 * eq3
    // mulmod_checked(&mut self, a) computes self = self * a
    eq0.mulmod_checked(&eq1);
    eq0.mulmod_checked(&eq2);
    eq0.mulmod_checked(&eq3);

    eq0
}

/// Check if Uint256 value is zero.
/// Returns 1 if zero, 0 otherwise. Adds constraints.
pub fn eqz(x: &Uint256) -> Bn254Fr {
    let zero = Uint256::new();
    eq(x, &zero)
}

/// Conditional select: returns a if cond == 1, b if cond == 0.
/// cond must be either 0 or 1. Adds constraints.
pub fn mux(cond: &Bn254Fr, a: &Uint256, b: &Uint256) -> Uint256 {
    let mut result = Uint256::new();
    for i in 0..UINT256_NLIMBS {
        raw::mux(result.limb_mut(i), cond.handle(), a.limb(i), b.limb(i));
    }
    result
}

/// Add equality constraints for two Uint256 values.
pub fn assert_equal(x: &Uint256, y: &Uint256) {
    for i in 0..UINT256_NLIMBS {
        raw::assert_equal(x.limb(i), y.limb(i));
    }
}

// ============= Arithmetic Operations =============

/// Number of bits per limb
const LIMB_BITS: usize = 64;

/// A five-handle view aliasing `val`'s four limbs followed by `carry`.
///
/// The carry/borrow chains at the bigint layer write a `count + 1`-limb result, where the top
/// limb is the carry out. Aliasing the caller's handles into that shape means the chain writes
/// straight into the `Uint256Cc`, with no intermediate whose handles would have to be moved --
/// the same trick `mul_wide` uses.
fn alias_cc(res: &Uint256Cc) -> [bn254fr_t; UINT256_NLIMBS + 1] {
    let mut out = [bn254fr_t::default(); UINT256_NLIMBS + 1];
    out[..UINT256_NLIMBS].copy_from_slice(&res.val.limbs);
    out[UINT256_NLIMBS] = *res.carry.handle();
    out
}

/// Perform uint256 addition with carry, adds constraints.
pub fn add_cc(a: &Uint256, b: &Uint256) -> Uint256Cc {
    let res = Uint256Cc {
        val: Uint256::new(),
        carry: Bn254Fr::new(),
    };

    let mut out = alias_cc(&res);
    crate::bn254fr_bigint::add_checked_limbs(
        &mut out,
        a.limbs_all(),
        b.limbs_all(),
        LIMB_BITS as u32,
    );

    res
}

/// Perform uint256 subtraction with borrow, adds constraints.
///
/// The `carry` field holds the borrow out, meaning underflow.
pub fn sub_cc(a: &Uint256, b: &Uint256) -> Uint256Cc {
    let res = Uint256Cc {
        val: Uint256::new(),
        carry: Bn254Fr::new(),
    };

    let mut out = alias_cc(&res);
    crate::bn254fr_bigint::sub_checked_limbs(
        &mut out,
        a.limbs_all(),
        b.limbs_all(),
        LIMB_BITS as u32,
    );

    res
}

/// Perform uint256 multiplication returning 512-bit result, adds constraints.
pub fn mul_wide(a: &Uint256, b: &Uint256) -> Uint256Wide {
    let res = Uint256Wide {
        lo: Uint256::new(),
        hi: Uint256::new(),
    };

    // A contiguous 8-limb view aliasing `lo || hi`, so the product lands directly in the
    // result, so there is no intermediate whose handles would have to be moved out.
    let mut out = [bn254fr_t::default(); 2 * UINT256_NLIMBS];
    out[..UINT256_NLIMBS].copy_from_slice(&res.lo.limbs);
    out[UINT256_NLIMBS..].copy_from_slice(&res.hi.limbs);

    crate::bn254fr_bigint::mul_checked_limbs(
        &mut out,
        a.limbs_all(),
        b.limbs_all(),
        LIMB_BITS as u32,
    );

    res
}


/// Moves exactly `UINT256_NLIMBS` limbs out of a `Vec` into the array `Uint256` holds.


/// Perform uint256 multiplication returning low 256 bits, adds constraints.
pub fn mul_lo(a: &Uint256, b: &Uint256) -> Uint256 {
    mul_wide(a, b).lo
}

/// Perform uint256 multiplication returning high 256 bits, adds constraints.
pub fn mul_hi(a: &Uint256, b: &Uint256) -> Uint256 {
    mul_wide(a, b).hi
}

/// Perform modular inverse: out = a^(-1) mod m, adds constraints.
///
/// The host inverts out of circuit; the proof is `out * a mod m == 1`, built from the checked
/// multiply and the checked division so every step is bound.
///
/// The verification reduces a 512-bit product modulo `m`, so `m` inherits
/// [`uint512_mod`]'s precondition: its most significant limb must be nonzero.
pub fn invmod(a: &Uint256, m: &Uint256) -> Uint256 {
    let mut result = Uint256::new();

    // Call host function to compute inverse
    unsafe {
        _uint256_invmod(&mut result, a, m);
    }
    #[cfg(feature = "fault-injection")]
    crate::fault::corrupt_uint256_invmod(&mut result);

    // Verify: result * a === 1 (mod m), against CONSTANTS.
    //
    // `Uint256::from_u64(1)` sets its limbs with the unchecked `raw::set_u64`, so comparing
    // against one pinned nothing -- a prover could choose all four of its limbs to match
    // whatever `remainder` came out as. See A26.
    let remainder = mul_wide(&result, a).modulo(m);
    raw::assert_equal_u32(remainder.limb(0), 1);
    for i in 1..UINT256_NLIMBS {
        raw::assert_equal_u32(remainder.limb(i), 0);
    }

    result
}

/// Perform 512-bit mod operation: (lo, hi) mod m, adds constraints.
///
/// **`m`'s most significant limb must be nonzero** -- that is, `m >= 2^192`. See
/// [`Uint256Wide::divide_qr_normalized`] for why, and for why the bound is not enforced at
/// runtime. Violating it is safe but opaque: the proof is rejected with nothing pointing at
/// the modulus.
pub fn uint512_mod(wide: &Uint256Wide, m: &Uint256) -> Uint256 {
    wide.modulo(m)
}
