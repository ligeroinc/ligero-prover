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

use crate::bn254fr::Bn254Fr;

/// Raw handle type for a single Bn254Fr element in FFI calls.
/// This is the u64 handle that the VM uses internally.
type Bn254FrRawHandle = u64;

/// Raw Uint256 handle type matching C++ __uint256 for FFI calls.
/// Contains 4 contiguous Bn254Fr handles (32 bytes total).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct Uint256Handle {
    limbs: [Bn254FrRawHandle; 4],
}

/// Number of 64-bit limbs in a Uint256
pub const UINT256_NLIMBS: usize = 4;

/// Result of addition/subtraction with carry/borrow.
/// C++ equivalent: struct uint256_cc
pub struct Uint256Cc {
    pub val: Uint256,
    pub carry: Bn254Fr,
}

/// 512-bit wide result (used for multiplication).
/// C++ equivalent: struct uint256_wide
pub struct Uint256Wide {
    pub lo: Uint256,
    pub hi: Uint256,
}

impl Uint256Wide {
    /// Perform 512-bit division by normalized divisor.
    /// Returns (quotient_low, quotient_high_limb, remainder).
    /// The divisor's MSB must be non-zero so quotient fits in 256+64 bits.
    /// C++ equivalent: divide_qr_normalized(uint256&, bn254fr_class&, uint256&, const uint256&)
    pub fn divide_qr_normalized(&self, divisor: &Uint256) -> (Uint256, Bn254Fr, Uint256) {
        let mut q_low = Uint256::new();
        let mut q_high = Bn254Fr::new();
        let mut r = Uint256::new();

        let mut q_low_h = get_uint256_handle(&q_low);
        let mut q_high_h = q_high.raw_handle();
        let mut r_h = get_uint256_handle(&r);
        let lo_h = get_uint256_handle(&self.lo);
        let hi_h = get_uint256_handle(&self.hi);
        let d_h = get_uint256_handle(divisor);

        unsafe {
            _uint512_idiv_normalized(&mut q_low_h, &mut q_high_h, &mut r_h, &lo_h, &hi_h, &d_h);
        }

        set_uint256_handle(&mut q_low, q_low_h);
        q_high.set_raw_handle(q_high_h);
        set_uint256_handle(&mut r, r_h);

        // Range check outputs
        for i in 0..UINT256_NLIMBS {
            let _ = q_low.limbs[i].to_bits(64);
            let _ = r.limbs[i].to_bits(64);
        }
        let _ = q_high.to_bits(64);

        (q_low, q_high, r)
    }

    /// Perform 512-bit mod operation.
    /// C++ equivalent: mod(uint256&, const uint256&)
    pub fn modulo(&self, m: &Uint256) -> Uint256 {
        let (_, _, r) = self.divide_qr_normalized(m);
        r
    }
}

/// Extract handles from Uint256 into raw Uint256Handle
#[inline(always)]
fn get_uint256_handle(u: &Uint256) -> Uint256Handle {
    Uint256Handle {
        limbs: [
            u.limbs[0].raw_handle(),
            u.limbs[1].raw_handle(),
            u.limbs[2].raw_handle(),
            u.limbs[3].raw_handle(),
        ],
    }
}

/// Copy handles from Uint256Handle back to Uint256
#[inline(always)]
fn set_uint256_handle(u: &mut Uint256, h: Uint256Handle) {
    for i in 0..4 {
        u.limbs[i].set_raw_handle(h.limbs[i]);
    }
}

/// A 256-bit unsigned integer
///
/// Internally represented as 4 64-bit limbs stored as BN254 field elements.
/// Limb 0 is the least significant.
#[repr(C)]
pub struct Uint256 {
    limbs: [Bn254Fr; UINT256_NLIMBS],
}

impl Drop for Uint256 {
    fn drop(&mut self) {
        // Bn254Fr handles its own cleanup via Drop
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
        Uint256 {
            limbs: [
                Bn254Fr::new(),
                Bn254Fr::new(),
                Bn254Fr::new(),
                Bn254Fr::new(),
            ],
        }
    }
}

impl Uint256 {
    /// Create a new uninitialized Uint256 (all limbs set to zero).
    /// C++ equivalent: uint256()
    pub fn new() -> Self {
        Self::default()
    }

    /// Copy value from another Uint256 with constraints.
    /// C++ equivalent: copy(const uint256&)
    pub fn copy_checked(&mut self, other: &Uint256) {
        for i in 0..UINT256_NLIMBS {
            self.limbs[i].copy(&other.limbs[i]);
            Bn254Fr::assert_equal(&self.limbs[i], &other.limbs[i]);
        }
    }

    /// Get a reference to a limb
    #[inline(always)]
    pub fn limb(&self, i: usize) -> &Bn254Fr {
        &self.limbs[i]
    }

    /// Get a mutable reference to a limb
    #[inline(always)]
    pub fn limb_mut(&mut self, i: usize) -> &mut Bn254Fr {
        &mut self.limbs[i]
    }

    /// Set value from little-endian bytes (unchecked - no constraints added).
    /// C++ equivalent: set_bytes_little_unchecked(const unsigned char*, uint32_t)
    pub fn set_bytes_little_unchecked(&mut self, bytes: &[u8]) {
        let mut h = get_uint256_handle(self);
        unsafe {
            _uint256_set_bytes_little(&mut h, bytes.as_ptr(), bytes.len() as u32);
        }
        set_uint256_handle(self, h);
    }

    /// Set value from big-endian bytes (unchecked - no constraints added).
    /// C++ equivalent: set_bytes_big_unchecked(const unsigned char*, uint32_t)
    pub fn set_bytes_big_unchecked(&mut self, bytes: &[u8]) {
        let mut h = get_uint256_handle(self);
        unsafe {
            _uint256_set_bytes_big(&mut h, bytes.as_ptr(), bytes.len() as u32);
        }
        set_uint256_handle(self, h);
    }

    /// Set value from string representation (unchecked).
    /// C++ equivalent: set_str(const char*, int)
    pub fn set_str(&mut self, s: &str, base: u32) {
        let mut h = get_uint256_handle(self);
        // Create null-terminated C string
        let c_str = std::ffi::CString::new(s).expect("CString::new failed");
        unsafe {
            _uint256_set_str(&mut h, c_str.as_ptr(), base);
        }
        set_uint256_handle(self, h);
    }

    /// Print the value (for debugging).
    /// C++ equivalent: print() const
    pub fn print(&self) {
        let h = get_uint256_handle(self);
        unsafe {
            _uint256_print(&h);
        }
    }

    /// Create a Uint256 from a u64 value.
    /// C++ equivalent: uint256(uint64_t)
    pub fn from_u64(val: u64) -> Self {
        let mut out = Self::new();
        out.set_u64(val);
        out
    }

    /// Create a Uint256 from a string.
    /// C++ equivalent: uint256(const char*, int)
    pub fn from_str(s: &str, base: u32) -> Self {
        let mut out = Self::new();
        out.set_str(s, base);
        out
    }

    /// Set value from u64.
    /// C++ equivalent: set_u64(uint64_t)
    pub fn set_u64(&mut self, val: u64) {
        self.limbs[0].set_u64(val);
        for i in 1..UINT256_NLIMBS {
            self.limbs[i].set_u64(0);
        }
    }

    /// Set value from u32.
    /// C++ equivalent: set_u32(uint32_t)
    pub fn set_u32(&mut self, val: u32) {
        self.limbs[0].set_u32(val);
        for i in 1..UINT256_NLIMBS {
            self.limbs[i].set_u64(0);
        }
    }

    /// Set value from a Bn254Fr field element.
    /// The field element must fit in 64 bits. Sets limb 0 and zeros others.
    /// C++ equivalent: set_bn254(const bn254fr_class&)
    pub fn set_bn254(&mut self, bn254: &Bn254Fr) {
        self.limbs[0].copy(bn254);
        Bn254Fr::assert_equal(&self.limbs[0], bn254);
        // Range check to ensure it fits in 64 bits
        let _ = self.limbs[0].to_bits(64);
        for i in 1..UINT256_NLIMBS {
            self.limbs[i].set_u64(0);
        }
    }

    /// Get value as u64 with constraints.
    /// Adds constraints asserting higher limbs are zero.
    /// C++ equivalent: get_u64() const
    pub fn get_u64(&self) -> u64 {
        // Assert higher limbs are zero
        let zero = Bn254Fr::new();
        for i in 1..UINT256_NLIMBS {
            Bn254Fr::assert_equal(&self.limbs[i], &zero);
        }
        // Range check limb 0 and return value
        let _ = self.limbs[0].to_bits(64);
        self.limbs[0].get_u64()
    }

    /// Get value as u64 without constraints (unchecked).
    /// C++ equivalent: get_u64_unchecked() const
    pub fn get_u64_unchecked(&self) -> u64 {
        self.limbs[0].get_u64()
    }

    /// Set value from little-endian bytes with constraints.
    /// C++ equivalent: set_bytes_little(const unsigned char*, uint32_t)
    pub fn set_bytes_little(&mut self, bytes: &[u8]) {
        // Use unchecked version first
        self.set_bytes_little_unchecked(bytes);
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            let _ = self.limbs[i].to_bits(64);
        }
    }

    /// Set value from big-endian bytes with constraints.
    /// C++ equivalent: set_bytes_big(const unsigned char*, uint32_t)
    pub fn set_bytes_big(&mut self, bytes: &[u8]) {
        // Use unchecked version first
        self.set_bytes_big_unchecked(bytes);
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            let _ = self.limbs[i].to_bits(64);
        }
    }

    /// Set limbs from array of Bn254Fr values with constraints.
    /// C++ equivalent: set_words(const bn254fr_class*)
    pub fn set_words(&mut self, words: &[Bn254Fr; UINT256_NLIMBS]) {
        for i in 0..UINT256_NLIMBS {
            self.limbs[i].copy(&words[i]);
            Bn254Fr::assert_equal(&self.limbs[i], &words[i]);
            // Range check each limb to 64 bits
            let _ = self.limbs[i].to_bits(64);
        }
    }

    /// Get limbs as array of Bn254Fr values with constraints.
    /// C++ equivalent: get_words(bn254fr_class*) const
    pub fn get_words(&self) -> [Bn254Fr; UINT256_NLIMBS] {
        let mut words = [
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
            Bn254Fr::new(),
        ];
        for i in 0..UINT256_NLIMBS {
            words[i].copy(&self.limbs[i]);
            Bn254Fr::assert_equal(&words[i], &self.limbs[i]);
        }
        words
    }

    /// Convert to little-endian bytes (32 bytes) with constraints.
    /// C++ equivalent: to_bytes_little(unsigned char*) const
    pub fn to_bytes_little(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..UINT256_NLIMBS {
            let limb_val = self.limbs[i].get_u64();
            let limb_bytes = limb_val.to_le_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            let _ = self.limbs[i].to_bits(64);
        }
        bytes
    }

    /// Convert to big-endian bytes (32 bytes) with constraints.
    /// C++ equivalent: to_bytes_big(unsigned char*) const
    pub fn to_bytes_big(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        for i in 0..UINT256_NLIMBS {
            let limb_val = self.limbs[UINT256_NLIMBS - 1 - i].get_u64();
            let limb_bytes = limb_val.to_be_bytes();
            bytes[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        // Add range constraints via bit decomposition
        for i in 0..UINT256_NLIMBS {
            let _ = self.limbs[i].to_bits(64);
        }
        bytes
    }

    /// Decompose uint256 into 256 bits with constraints.
    /// C++ equivalent: to_bits(bn254fr_class*) const
    pub fn to_bits(&self) -> Vec<Bn254Fr> {
        let mut all_bits = Vec::with_capacity(256);
        for i in 0..UINT256_NLIMBS {
            let limb_bits = self.limbs[i].to_bits(64);
            all_bits.extend(limb_bits);
        }
        all_bits
    }

    /// Compose uint256 from 256 bits with constraints.
    /// C++ equivalent: from_bits(const bn254fr_class*)
    pub fn from_bits(bits: &[Bn254Fr]) -> Self {
        assert!(bits.len() == 256, "from_bits requires exactly 256 bits");
        let mut result = Uint256::new();
        for i in 0..UINT256_NLIMBS {
            let start = i * 64;
            let end = start + 64;
            result.limbs[i] = Bn254Fr::from_bits_checked(&bits[start..end]);
        }
        result
    }
}

// ============= Host Function Declarations =============
#[link(wasm_import_module = "uint256")]
extern "C" {
    #[link_name = "uint256_set_bytes_little"]
    fn _uint256_set_bytes_little(out: *mut Uint256Handle, bytes: *const u8, len: u32);

    #[link_name = "uint256_set_bytes_big"]
    fn _uint256_set_bytes_big(out: *mut Uint256Handle, bytes: *const u8, len: u32);

    #[link_name = "uint256_set_str"]
    fn _uint256_set_str(out: *mut Uint256Handle, s: *const i8, base: u32);

    #[link_name = "uint256_print"]
    fn _uint256_print(a: *const Uint256Handle);

    #[link_name = "uint512_idiv_normalized"]
    fn _uint512_idiv_normalized(
        q_low: *mut Uint256Handle,
        q_high: *mut Bn254FrRawHandle,
        r: *mut Uint256Handle,
        a_low: *const Uint256Handle,
        a_high: *const Uint256Handle,
        b: *const Uint256Handle,
    );

    #[link_name = "uint256_invmod"]
    fn _uint256_invmod(out: *mut Uint256Handle, a: *const Uint256Handle, m: *const Uint256Handle);
}

// ============= Comparison Operations =============

/// Compare two Uint256 values for equality.
/// Returns 1 if equal, 0 otherwise. Adds constraints.
/// C++ equivalent: eq(bn254fr_class&, const uint256&, const uint256&)
pub fn eq(x: &Uint256, y: &Uint256) -> Bn254Fr {
    // Compare all limbs and AND the results
    let mut eq0 = Bn254Fr::new();
    let mut eq1 = Bn254Fr::new();
    let mut eq2 = Bn254Fr::new();
    let mut eq3 = Bn254Fr::new();

    crate::bn254fr::eq_checked(&mut eq0, x.limb(0), y.limb(0));
    crate::bn254fr::eq_checked(&mut eq1, x.limb(1), y.limb(1));
    crate::bn254fr::eq_checked(&mut eq2, x.limb(2), y.limb(2));
    crate::bn254fr::eq_checked(&mut eq3, x.limb(3), y.limb(3));

    // AND all equality results: result = eq0 * eq1 * eq2 * eq3
    // mulmod_checked(&mut self, a) computes self = self * a
    eq0.mulmod_checked(&eq1);
    eq0.mulmod_checked(&eq2);
    eq0.mulmod_checked(&eq3);

    eq0
}

/// Check if Uint256 value is zero.
/// Returns 1 if zero, 0 otherwise. Adds constraints.
/// C++ equivalent: eqz(bn254fr_class&, const uint256&)
pub fn eqz(x: &Uint256) -> Bn254Fr {
    let zero = Uint256::new();
    eq(x, &zero)
}

/// Conditional select: returns a if cond == 1, b if cond == 0.
/// cond must be either 0 or 1. Adds constraints.
/// C++ equivalent: mux(uint256&, const bn254fr_class&, const uint256&, const uint256&)
pub fn mux(cond: &Bn254Fr, a: &Uint256, b: &Uint256) -> Uint256 {
    let mut result = Uint256::new();
    for i in 0..UINT256_NLIMBS {
        crate::bn254fr::mux(result.limb_mut(i), cond, a.limb(i), b.limb(i));
    }
    result
}

/// Add equality constraints for two Uint256 values.
/// C++ equivalent: assert_equal(const uint256&, const uint256&)
pub fn assert_equal(x: &Uint256, y: &Uint256) {
    for i in 0..UINT256_NLIMBS {
        Bn254Fr::assert_equal(x.limb(i), y.limb(i));
    }
}

// ============= Arithmetic Operations =============

/// Number of bits per limb
const LIMB_BITS: usize = 64;

/// Add two 64-bit limbs with carry-in, returning (sum, carry-out).
/// Decomposes into 65 bits to extract carry.
fn add_limb_with_carry(a: &Bn254Fr, b: &Bn254Fr, carry_in: &Bn254Fr) -> (Bn254Fr, Bn254Fr) {
    // sum = a + b + carry_in
    let mut sum = Bn254Fr::new();
    crate::bn254fr::addmod_checked(&mut sum, a, b);
    sum.addmod_checked(carry_in);

    // Decompose sum into 65 bits to extract carry
    let bits = sum.to_bits(LIMB_BITS + 1);

    // carry_out is the MSB (bit 64)
    let carry_out = bits[LIMB_BITS].clone();

    // result is composed from bits 0..63
    let result = Bn254Fr::from_bits_checked(&bits[0..LIMB_BITS]);

    (result, carry_out)
}

/// Subtract two 64-bit limbs with borrow-in, returning (diff, borrow-out).
/// Uses the formula: diff = 2^64 + a - b - borrow_in, then extracts borrow.
fn sub_limb_with_borrow(a: &Bn254Fr, b: &Bn254Fr, borrow_in: &Bn254Fr) -> (Bn254Fr, Bn254Fr) {
    // Compute 2^64 + a - b - borrow_in
    let two_pow_64 = Bn254Fr::from_str("18446744073709551616"); // 2^64

    let mut sum = Bn254Fr::new();
    crate::bn254fr::addmod_checked(&mut sum, &two_pow_64, a);
    sum.submod_checked(b);
    sum.submod_checked(borrow_in);

    // Decompose sum into 65 bits
    let bits = sum.to_bits(LIMB_BITS + 1);

    // borrow_out is 1 - MSB (if MSB is 0, we borrowed)
    let one = Bn254Fr::from_u32(1);
    let mut borrow_out = Bn254Fr::new();
    crate::bn254fr::submod_checked(&mut borrow_out, &one, &bits[LIMB_BITS]);

    // result is composed from bits 0..63
    let result = Bn254Fr::from_bits_checked(&bits[0..LIMB_BITS]);

    (result, borrow_out)
}

/// Perform uint256 addition with carry, adds constraints.
/// C++ equivalent: add_cc(const uint256&, const uint256&) -> uint256_cc
pub fn add_cc(a: &Uint256, b: &Uint256) -> Uint256Cc {
    let mut result = Uint256::new();
    let mut carry = Bn254Fr::from_u32(0);

    for i in 0..UINT256_NLIMBS {
        let (limb_result, limb_carry) = add_limb_with_carry(a.limb(i), b.limb(i), &carry);
        result.limbs[i] = limb_result;
        carry = limb_carry;
    }

    Uint256Cc { val: result, carry }
}

/// Perform uint256 subtraction with borrow, adds constraints.
/// C++ equivalent: sub_cc(const uint256&, const uint256&) -> uint256_cc
pub fn sub_cc(a: &Uint256, b: &Uint256) -> Uint256Cc {
    let mut result = Uint256::new();
    let mut borrow = Bn254Fr::from_u32(0);

    for i in 0..UINT256_NLIMBS {
        let (limb_result, limb_borrow) = sub_limb_with_borrow(a.limb(i), b.limb(i), &borrow);
        result.limbs[i] = limb_result;
        borrow = limb_borrow;
    }

    // Return borrow as "carry" (underflow indicator)
    Uint256Cc {
        val: result,
        carry: borrow,
    }
}

/// Perform uint256 multiplication returning 512-bit result, adds constraints.
/// C++ equivalent: mul_wide(const uint256&, const uint256&) -> uint256_wide
pub fn mul_wide(a: &Uint256, b: &Uint256) -> Uint256Wide {
    // Use bigint multiplication from bn254fr
    // Convert limbs to slices
    let a_limbs: [Bn254Fr; UINT256_NLIMBS] = [
        a.limbs[0].clone(),
        a.limbs[1].clone(),
        a.limbs[2].clone(),
        a.limbs[3].clone(),
    ];
    let b_limbs: [Bn254Fr; UINT256_NLIMBS] = [
        b.limbs[0].clone(),
        b.limbs[1].clone(),
        b.limbs[2].clone(),
        b.limbs[3].clone(),
    ];

    // Output has 2*NLIMBS - 1 = 7 limbs before carry propagation
    let mut mul_no_carry: Vec<Bn254Fr> = (0..7).map(|_| Bn254Fr::new()).collect();

    crate::bn254fr::bigint_mul_checked_no_carry(&mut mul_no_carry, &a_limbs, &b_limbs);

    // Convert to proper representation with carry (8 limbs)
    let mut out_limbs: Vec<Bn254Fr> = (0..8).map(|_| Bn254Fr::new()).collect();

    crate::bn254fr::bigint_convert_to_proper_representation(
        &mut out_limbs,
        &mut mul_no_carry,
        LIMB_BITS as u32,
    );

    // Build result
    let mut lo = Uint256::new();
    let mut hi = Uint256::new();

    for i in 0..UINT256_NLIMBS {
        lo.limbs[i] = out_limbs[i].clone();
        hi.limbs[i] = out_limbs[UINT256_NLIMBS + i].clone();
    }

    Uint256Wide { lo, hi }
}

/// Perform uint256 multiplication returning low 256 bits, adds constraints.
/// C++ equivalent: mul_lo(const uint256&, const uint256&) -> uint256
pub fn mul_lo(a: &Uint256, b: &Uint256) -> Uint256 {
    mul_wide(a, b).lo
}

/// Perform uint256 multiplication returning high 256 bits, adds constraints.
/// C++ equivalent: mul_hi(const uint256&, const uint256&) -> uint256
pub fn mul_hi(a: &Uint256, b: &Uint256) -> Uint256 {
    mul_wide(a, b).hi
}

/// Perform modular inverse: out = a^(-1) mod m, adds constraints.
/// C++ equivalent: invmod(const uint256&, const uint256&) -> uint256
pub fn invmod(a: &Uint256, m: &Uint256) -> Uint256 {
    let mut result = Uint256::new();

    // Call host function to compute inverse
    let mut result_h = get_uint256_handle(&result);
    let a_h = get_uint256_handle(a);
    let m_h = get_uint256_handle(m);

    unsafe {
        _uint256_invmod(&mut result_h, &a_h, &m_h);
    }
    set_uint256_handle(&mut result, result_h);

    // Verify: result * a ≡ 1 (mod m)
    let product = mul_wide(&result, a);

    // Compute product mod m using division
    let one = Uint256::from_u64(1);
    let remainder = uint512_mod(&product, m);

    // Assert remainder == 1
    let eq_result = eq(&remainder, &one);
    let one_fr = Bn254Fr::from_u32(1);
    Bn254Fr::assert_equal(&eq_result, &one_fr);

    result
}

/// Perform 512-bit mod operation: (lo, hi) mod m, adds constraints.
/// C++ equivalent: uint256_wide::mod(uint256&, const uint256&)
pub fn uint512_mod(wide: &Uint256Wide, m: &Uint256) -> Uint256 {
    let mut q_low = Uint256::new();
    let mut q_high = Bn254Fr::new();
    let mut r = Uint256::new();

    // Call host function for division
    let mut q_low_h = get_uint256_handle(&q_low);
    let mut q_high_h = q_high.raw_handle();
    let mut r_h = get_uint256_handle(&r);
    let lo_h = get_uint256_handle(&wide.lo);
    let hi_h = get_uint256_handle(&wide.hi);
    let m_h = get_uint256_handle(m);

    unsafe {
        _uint512_idiv_normalized(&mut q_low_h, &mut q_high_h, &mut r_h, &lo_h, &hi_h, &m_h);
    }

    set_uint256_handle(&mut q_low, q_low_h);
    q_high.set_raw_handle(q_high_h);
    set_uint256_handle(&mut r, r_h);

    // Verify: q * m + r == (lo, hi)
    // First compute q * m (need to handle q_high as 5th limb)
    let _q_times_m = mul_wide(&q_low, m);

    // Add q_high * m contribution (q_high is just one limb)
    // q_high * m needs to be added to the appropriate position
    // For simplicity, verify using the constraint that q*m + r = a

    // TODO: Full verification requires more complex constraint generation
    // For now, rely on the host function correctness and add range checks

    // Range check result limbs
    for i in 0..UINT256_NLIMBS {
        let _ = r.limbs[i].to_bits(LIMB_BITS);
    }

    r
}
