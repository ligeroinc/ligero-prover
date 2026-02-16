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

//! BN254 Scalar Field Operations for Ligetron

use crate::api::*;
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, Ordering};

/// A BN254 scalar field element
///
/// This is an opaque handle to a field element managed by the Ligetron backend.
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct bn254fr_t {
    pub handle: u64,
}

#[repr(C)]
pub struct Bn254Fr {
    data: bn254fr_t,
    constrained: AtomicBool,
}

impl Drop for Bn254Fr {
    fn drop(&mut self) {
        unsafe {
            _bn254fr_free(&mut self.data);
        }
    }
}

impl Clone for Bn254Fr {
    fn clone(&self) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_copy(&mut out.data, &self.data);
        }

        if self.is_constrained() {
            unsafe {
                _bn254fr_assert_equal(&out.data, &self.data);
            }
            out.set_constrained(true);
        }
        out
    }
}

// ============= Operation helper macros =============

// Internal helper function
#[inline(always)]
fn handle_swap(a: &mut bn254fr_t, b: &mut bn254fr_t) {
    //    std::mem::swap(&mut a.handle, &mut b.handle);
    let th = a.handle;
    a.handle = b.handle;
    b.handle = th;
}

macro_rules! bn254fr_unary {
    ($op:ident, $out:expr, $a:expr) => {
        if $out.is_constrained() {
            let mut tmp = Bn254Fr::new();
            unsafe {
                paste::paste! {
                    [<_bn254fr_ $op>](&mut tmp.data, &$a.data);
                }
            }
            handle_swap(&mut tmp.data, &mut $out.data);
            $out.set_constrained(false);
        } else {
            unsafe {
                paste::paste! {
                    [<_bn254fr_ $op>](&mut $out.data, &$a.data);
                }
            }
        }
    };
}

macro_rules! bn254fr_binary {
    ($op:ident, $out:expr, $a:expr, $b:expr) => {
        if $out.is_constrained() {
            let mut tmp = Bn254Fr::new();
            unsafe {
                paste::paste! {
                    [<_bn254fr_ $op>](&mut tmp.data, &$a.data, &$b.data);
                }
            }
            handle_swap(&mut tmp.data, &mut $out.data);
            $out.set_constrained(false);
        } else {
            unsafe {
                paste::paste! {
                    [<_bn254fr_ $op>](&mut $out.data, &$a.data, &$b.data);
                }
            }
        }
    };
}
macro_rules! unary_constrained {
    ($op:ident, $out:expr, $a:expr) => {
        let mut tmp = Bn254Fr::new();
        $op(&mut tmp, $a);
        handle_swap(&mut $out.data, &mut tmp.data);
        $out.set_constrained(true);
    };
}

macro_rules! binary_constrained {
    ($op:ident, $out:expr, $a:expr) => {
        let mut tmp = Bn254Fr::new();
        $op(&mut tmp, $out, $a);
        handle_swap(&mut $out.data, &mut tmp.data);
        $out.set_constrained(true);
    };
}

impl Bn254Fr {
    /// Create a new uninitialized field element
    /// You must call one of the `set_*` methods before using this value.
    #[inline(always)]
    pub fn new() -> Self {
        let mut out = Bn254Fr {
            data: bn254fr_t::default(),
            constrained: false.into(),
        };
        unsafe {
            _bn254fr_alloc(&mut out.data);
        };
        out
    }

    /// Get the raw u64 handle for FFI calls.
    /// This is used by higher-level modules (like uint256) that need to pass
    /// handles to host functions.
    #[inline(always)]
    pub fn raw_handle(&self) -> u64 {
        self.data.handle
    }

    /// Set the raw u64 handle from FFI calls.
    /// This is used by higher-level modules (like uint256) after host functions
    /// have modified the handle.
    #[inline(always)]
    pub fn set_raw_handle(&mut self, handle: u64) {
        self.data.handle = handle;
    }

    /// Construct from u32 constant
    pub fn from_u32(value: u32) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_alloc(&mut out.data);
            _bn254fr_set_u32(&mut out.data, value);
        }
        out
    }

    /// Construct from u64 constant
    pub fn from_u64(value: u64) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_alloc(&mut out.data);
            _bn254fr_set_u64(&mut out.data, value);
        }
        out
    }

    /// Construct field element from a C-style string (decimal or hex with 0x prefix)
    pub fn from_c_str(str_ptr: *const i8) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_alloc(&mut out.data);
            _bn254fr_set_str(&mut out.data, str_ptr, 0);
        }
        out
    }

    /// Construct field element from a string (decimal or hex with 0x prefix)
    pub fn from_str(s: &str) -> Self {
        let c_str = CString::new(s).expect("Error parsing numeric string");
        Self::from_c_str(c_str.as_ptr())
    }

    /// Construct field element as a copy (does not copy constraints)
    pub fn copy_from(src: Self) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_copy(&mut out.data, &src.data);
        }
        out
    }

    /// Copy value from another field element in-place
    /// Mirrors C++ bn254fr_copy
    pub fn copy(&mut self, src: &Bn254Fr) {
        unsafe {
            _bn254fr_copy(&mut self.data, &src.data);
        }
    }

    pub fn is_constrained(&self) -> bool {
        self.constrained.load(Ordering::Relaxed)
    }

    fn set_constrained(&self, value: bool) {
        self.constrained.store(value, Ordering::Relaxed);
    }

    #[inline(always)]
    pub fn clear(&mut self) {
        if self.is_constrained() {
            unsafe {
                _bn254fr_free(&mut self.data);
                _bn254fr_alloc(&mut self.data);
            }
            self.set_constrained(false);
        }
    }

    /// Set field element to a u32 constant
    pub fn set_u32(&mut self, value: u32) {
        self.clear();
        unsafe {
            _bn254fr_set_u32(&mut self.data, value);
        }
    }

    /// Set field element to a u64 constant
    pub fn set_u64(&mut self, value: u64) {
        self.clear();
        unsafe {
            _bn254fr_set_u64(&mut self.data, value);
        }
    }

    /// Set field element from a string
    pub fn set_str(&mut self, s: &str, base: u32) {
        self.clear();
        let c_str = CString::new(s).expect("Error parsing numeric string");
        unsafe {
            _bn254fr_set_str(&mut self.data, c_str.as_ptr(), base);
        }
    }

    /// Set field element from byte buffer in little-endian order
    pub fn set_bytes_little(&mut self, bytes: &[u8]) {
        self.clear();
        unsafe {
            _bn254fr_set_bytes(&mut self.data, bytes.as_ptr(), bytes.len() as u32, -1);
        }
    }

    /// Set field element from byte buffer in big-endian order
    pub fn set_bytes_big(&mut self, bytes: &[u8]) {
        self.clear();
        unsafe {
            _bn254fr_set_bytes(&mut self.data, bytes.as_ptr(), bytes.len() as u32, 1);
        }
    }

    /// Get field element as u64 (may truncate for large values)
    pub fn get_u64(&self) -> u64 {
        unsafe { _bn254fr_get_u64(&self.data) }
    }

    /// Print field element for debugging (base 10 or 16)
    pub fn print_dec(&self) {
        unsafe {
            _bn254fr_print(&self.data, 10);
        }
    }

    /// Print field element for debugging (base 10 or 16)
    pub fn print_hex(&self) {
        unsafe {
            _bn254fr_print(&self.data, 16);
        }
    }

    /// Decompose field element into bits
    pub fn to_bits(&self, count: usize) -> Vec<Bn254Fr> {
        let bits: Vec<Bn254Fr> = vec![Bn254Fr::new(); count];

        if (count < 1) || (count > 254) {
            assert_one(0);
            return bits;
        }

        let mut out_buff: Vec<bn254fr_t> = vec![bn254fr_t::default(); count];
        unsafe {
            for i in 0..count {
                out_buff[i].handle = bits[i].data.handle;
            }

            _bn254fr_to_bits_checked(&mut out_buff[0], &self.data, count as u32);
        }

        for i in 0..count {
            bits[i].set_constrained(true);
        }
        self.set_constrained(true);
        bits
    }

    /// Compose field element from bits with constraints
    pub fn from_bits_checked(bits: &[Bn254Fr]) -> Bn254Fr {
        let count = bits.len();
        if count < 1 || count > 254 {
            assert_one(0);
            return Bn254Fr::new();
        }

        let out = Bn254Fr::new();

        // Build array of handles from bits
        let mut bits_buff: Vec<bn254fr_t> = vec![bn254fr_t::default(); count];
        unsafe {
            for i in 0..count {
                bits_buff[i].handle = bits[i].data.handle;
            }
            _bn254fr_from_bits_checked(
                &out.data as *const bn254fr_t as *mut bn254fr_t,
                &bits_buff[0],
                count as u32,
            );
        }

        for bit in bits {
            bit.set_constrained(true);
        }
        out.set_constrained(true);
        out
    }

    // ============= In-place Arithmetic Operations =============

    /// self = self + a mod p
    pub fn addmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(addmod, self, self, a);
    }

    /// self = self - a mod p
    pub fn submod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(submod, self, self, a);
    }

    /// self = self * a mod p
    pub fn mulmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(mulmod, self, self, a);
    }

    /// self = self / a mod p
    pub fn divmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(divmod, self, self, a);
    }

    /// self = self^a mod p
    pub fn powmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(powmod, self, self, a);
    }

    /// self = self^(-1) mod p
    pub fn invmod(&mut self) {
        bn254fr_unary!(invmod, self, self);
    }

    /// self = -self mod p
    pub fn negmod(&mut self) {
        bn254fr_unary!(negmod, self, self);
    }

    /// self = self / a (integer division)
    pub fn idiv(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(idiv, self, self, a);
    }

    /// self = self % a (integer remainder)
    pub fn irem(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(irem, self, self, a);
    }

    // ============= Checked In-place Arithmetic Operations =============

    /// self = self + a mod p (checked version)
    pub fn addmod_checked(&mut self, a: &Bn254Fr) {
        binary_constrained!(addmod_checked, self, a);
    }

    /// self = self - a mod p (checked version)
    pub fn submod_checked(&mut self, a: &Bn254Fr) {
        binary_constrained!(submod_checked, self, a);
    }

    /// self = self * a mod p (checked version)
    pub fn mulmod_checked(&mut self, a: &Bn254Fr) {
        binary_constrained!(mulmod_checked, self, a);
    }

    pub fn mulmod_constant_checked(&mut self, k: &Bn254Fr) {
        binary_constrained!(mulmod_constant_checked, self, k);
    }

    /// self = self / a mod p (checked version)
    pub fn divmod_checked(&mut self, a: &Bn254Fr) {
        binary_constrained!(divmod_checked, self, a);
    }

    pub fn divmod_constant_checked(&mut self, k: &Bn254Fr) {
        binary_constrained!(divmod_constant_checked, self, k);
    }

    /// self = self * a mod p (checked version)
    pub fn negmod_checked(&mut self, a: &Bn254Fr) {
        unary_constrained!(negmod_checked, self, a);
    }

    /// self = self * a mod p (checked version)
    pub fn invmod_checked(&mut self, a: &Bn254Fr) {
        unary_constrained!(invmod_checked, self, a);
    }

    // ============= Bitwise Operations =============

    /// self = self & a
    pub fn band(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(band, self, self, a);
    }

    /// self = self | a
    pub fn bor(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(bor, self, self, a);
    }

    /// self = self ^ a
    pub fn bxor(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(bxor, self, self, a);
    }

    /// self = ~self
    pub fn bnot(&mut self) {
        bn254fr_unary!(bnot, self, self);
    }

    // ============= Shift Operations =============

    ///
    /// self = a >> k (field shift right).
    /// For 0 <= k <= p/2:  self = a / (2^k) mod p.
    /// For p/2 < k < p:    self = a << (p - k).
    ///
    pub fn shrmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(shrmod, self, self, a);
    }

    ///
    /// self = a << k (field shift left).
    /// For 0 <= k <= p/2: self = (a * 2^k & (2^b - 1)) mod p, where b = bit length of p.
    /// For p/2 < k < p:    self = a >> (p - k).
    ///
    pub fn shlmod(&mut self, a: &Bn254Fr) {
        bn254fr_binary!(shlmod, self, self, a);
    }

    /// Return true if self == 0
    pub fn is_zero(&mut self) -> bool {
        unsafe { _bn254fr_eqz(&self.data) }
    }

    // ============= Arithmetic Constraint Assertions =============

    /// Assert a == b in the constraint system
    pub fn assert_equal(a: &Bn254Fr, b: &Bn254Fr) {
        unsafe {
            _bn254fr_assert_equal(&a.data, &b.data);
        }
        a.set_constrained(true);
        b.set_constrained(true);
    }

    /// Assert self == a + b (enforces a linear constraint)
    #[inline(always)]
    pub fn assert_add(out: &Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
        unsafe {
            _bn254fr_assert_add(&out.data, &a.data, &b.data);
        }
        a.set_constrained(true);
        b.set_constrained(true);
        out.set_constrained(true);
    }

    /// Assert self == a * b (enforces a quadratic constraint)
    #[inline(always)]
    pub fn assert_mul(out: &Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
        unsafe {
            _bn254fr_assert_mul(&out.data, &a.data, &b.data);
        }
        a.set_constrained(true);
        b.set_constrained(true);
        out.set_constrained(true);
    }

    /// Assert self == a * k (enforces k linar constraints)
    #[inline(always)]
    pub fn assert_mulc(out: &Bn254Fr, a: &Bn254Fr, k: &Bn254Fr) {
        unsafe {
            _bn254fr_assert_mulc(&out.data, &a.data, &k.data);
        }
        a.set_constrained(true);
        out.set_constrained(true);
    }
}

// ============= Arithmetic Operations =============

/// out = a + b mod p
pub fn addmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(addmod, out, a, b);
}

/// out = a - b mod p
pub fn submod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(submod, out, a, b);
}

/// out = a * b mod p
pub fn mulmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(mulmod, out, a, b);
}

/// out = a / b mod p
pub fn divmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(divmod, out, a, b);
}

/// out = a^(-1) mod p
pub fn invmod(out: &mut Bn254Fr, a: &Bn254Fr) {
    bn254fr_unary!(invmod, out, a);
}

/// out = -a mod p
pub fn negmod(out: &mut Bn254Fr, a: &Bn254Fr) {
    bn254fr_unary!(negmod, out, a);
}

/// out = a^b mod p
pub fn powmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(powmod, out, a, b);
}

/// out = a / b (integer division)
pub fn idiv(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(idiv, out, a, b);
}

/// out = a % b (integer remainder)
pub fn irem(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(irem, out, a, b);
}

// ============= Comparisons =============

/// Return true if self == other
pub fn eq(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_eq(&a.data, &b.data) }
}

/// Return true if self < other
pub fn lt(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_lt(&a.data, &b.data) }
}

/// Return true if self <= other
pub fn lte(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_lte(&a.data, &b.data) }
}

/// Return true if self > other
pub fn gt(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_gt(&a.data, &b.data) }
}

/// Return true if self >= other
pub fn gte(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_gte(&a.data, &b.data) }
}

// ============= Logical Operations =============

///  Return true if both a and b are nonzero.
pub fn land(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_land(&a.data, &b.data) }
}

///  Return true if both a and b are nonzero.
pub fn lor(a: &Bn254Fr, b: &Bn254Fr) -> bool {
    unsafe { _bn254fr_lor(&a.data, &b.data) }
}

// ============= Bitwise Operations =============

/// out = a & b
pub fn band(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(band, out, a, b);
}

/// out = a | b
pub fn bor(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(bor, out, a, b);
}

/// out = a ^ b
pub fn bxor(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(bxor, out, a, b);
}

/// out = ~a
pub fn bnot(out: &mut Bn254Fr, a: &Bn254Fr) {
    bn254fr_unary!(bnot, out, a);
}

// ============= Shift Operations =============

///
/// out = a >> k (field shift right).
/// For 0 <= k <= p/2:  out = a / (2^k) mod p.
/// For p/2 < k < p:    out = a << (p - k).
///
pub fn shrmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(shrmod, out, a, b);
}

///
/// out = a << k (field shift left).
/// For 0 <= k <= p/2: out = (a * 2^k & (2^b - 1)) mod p, where b = bit length of p.
/// For p/2 < k < p:    out = a >> (p - k).
///
pub fn shlmod(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(shlmod, out, a, b);
}

// ============= Checked Operations (with constraints) =============

/// Checked addition: out = a + b with constraint
pub fn addmod_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(addmod, out, a, b);
    Bn254Fr::assert_add(out, a, b);
}

/// Checked subtraction: out = a - b with constraint
pub fn submod_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(submod, out, a, b);
    Bn254Fr::assert_add(a, out, b);
}

/// Checked multiplication: out = a * b with constraint
pub fn mulmod_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(mulmod, out, a, b);
    Bn254Fr::assert_mul(out, a, b);
}

/// Checked multiplication: out = a * b with constraint
pub fn mulmod_constant_checked(out: &mut Bn254Fr, a: &Bn254Fr, k: &Bn254Fr) {
    bn254fr_binary!(mulmod, out, a, k);
    Bn254Fr::assert_mulc(out, a, k);
}

/// Checked division: out = a / b with constraint
pub fn divmod_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    bn254fr_binary!(divmod, out, a, b);
    Bn254Fr::assert_mul(a, out, b);
}

/// Checked multiplication: out = a * b with constraint
pub fn divmod_constant_checked(out: &mut Bn254Fr, a: &Bn254Fr, k: &Bn254Fr) {
    bn254fr_binary!(divmod, out, a, k);
    Bn254Fr::assert_mulc(a, out, k);
}

/// out = -a mod p
pub fn negmod_checked(out: &mut Bn254Fr, a: &Bn254Fr) {
    let zero = Bn254Fr::from_u32(0);
    bn254fr_unary!(negmod, out, a);
    Bn254Fr::assert_add(&zero, out, a);
}

/// out = a^(-1) mod p
pub fn invmod_checked(out: &mut Bn254Fr, a: &Bn254Fr) {
    let one = Bn254Fr::from_u32(1);
    bn254fr_unary!(invmod, out, a);
    Bn254Fr::assert_mul(&one, out, a);
}

/// out = 1 if x == 0, 0 otherwise (with constraints)
/// Implements the technique: out = -x * inv + 1 where inv = 1/x if x != 0, else 0
pub fn eqz_checked(out: &mut Bn254Fr, x: &Bn254Fr) {
    let one = Bn254Fr::from_u32(1);
    let zero = Bn254Fr::from_u32(0);

    // Compute inverse if x != 0, else use 0
    let mut inv = Bn254Fr::new();
    if x.get_u64() != 0 {
        invmod(&mut inv, x);
    }
    // else inv stays 0

    // out = -x * inv + 1
    let mut neg_x = Bn254Fr::new();
    negmod_checked(&mut neg_x, x);

    let mut mul_res = Bn254Fr::new();
    mulmod_checked(&mut mul_res, &neg_x, &inv);

    addmod_checked(out, &mul_res, &one);

    // Assert x * out == 0
    let mut check = Bn254Fr::new();
    mulmod_checked(&mut check, x, out);
    Bn254Fr::assert_equal(&check, &zero);
}

/// out = 1 if a == b, 0 otherwise (with constraints)
pub fn eq_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    let mut sub_res = Bn254Fr::new();
    submod_checked(&mut sub_res, a, b);
    eqz_checked(out, &sub_res);
}

// ============= Misc =============

/// Conditional selection: out = cond ? a1 : a0, sets constraints
pub fn mux(out: &mut Bn254Fr, cond: &Bn254Fr, a0: &Bn254Fr, a1: &Bn254Fr) {
    // Assert that cond has a value of ether 0 or 1
    let one = Bn254Fr::from_u32(1);
    assert_one(lte(&cond, &one));

    // Implementing as: out = a0 + cond * (a1 - a0)
    let mut tmp = Bn254Fr::new();
    submod_checked(&mut tmp, a1, a0);
    tmp.mulmod_checked(cond);
    addmod_checked(out, &a0, &tmp)
}

pub fn mux2(
    out: &mut Bn254Fr,
    s0: &Bn254Fr,
    s1: &Bn254Fr,
    a0: &Bn254Fr,
    a1: &Bn254Fr,
    a2: &Bn254Fr,
    a3: &Bn254Fr,
) {
    // Assert that conditions have a value of ether 0 or 1
    let one = Bn254Fr::from_u32(1);
    assert_one(lte(s0, &one));
    assert_one(lte(s1, &one));

    let mut tmp1 = Bn254Fr::new();
    let mut tmp2 = Bn254Fr::new();

    mux(&mut tmp1, s0, a0, a1);
    mux(&mut tmp2, s0, a2, a3);
    mux(out, s1, &tmp1, &tmp2)
}

pub fn oblivious_if(out: &mut Bn254Fr, cond: bool, t: &Bn254Fr, f: &Bn254Fr) {
    let cond_fr = Bn254Fr::from_u32(cond as u32);
    mux(out, &cond_fr, f, t)
}

// ============= Bigint Operations (for uint256) =============

/// Compute product of two big integers without carry propagation.
/// Used internally by uint256 multiplication.
/// out must have length 2*count-1, a and b must have length count.
pub fn bigint_mul_checked_no_carry(out: &mut [Bn254Fr], a: &[Bn254Fr], b: &[Bn254Fr]) {
    let count = a.len();
    assert_eq!(b.len(), count);
    assert_eq!(out.len(), 2 * count - 1);

    // Extract handles into contiguous arrays
    let a_handles: Vec<u64> = a.iter().map(|f| f.raw_handle()).collect();
    let b_handles: Vec<u64> = b.iter().map(|f| f.raw_handle()).collect();
    let mut out_handles: Vec<u64> = out.iter().map(|f| f.raw_handle()).collect();

    unsafe {
        _bn254fr_bigint_mul_checked_no_carry(
            out_handles.as_mut_ptr(),
            a_handles.as_ptr(),
            b_handles.as_ptr(),
            count as u32,
        );
    }

    // Copy handles back
    for (i, h) in out_handles.into_iter().enumerate() {
        out[i].set_raw_handle(h);
    }
}

/// Convert big integer to proper representation with carry propagation.
/// Used internally by uint256 multiplication.
/// out must have length count+1, inp must have length count.
pub fn bigint_convert_to_proper_representation(
    out: &mut [Bn254Fr],
    inp: &mut [Bn254Fr],
    bits: u32,
) {
    let count = inp.len();
    assert_eq!(out.len(), count + 1);

    // Extract handles into contiguous arrays
    let mut inp_handles: Vec<u64> = inp.iter().map(|f| f.raw_handle()).collect();
    let mut out_handles: Vec<u64> = out.iter().map(|f| f.raw_handle()).collect();

    unsafe {
        _bn254fr_bigint_convert_to_proper_representation(
            out_handles.as_mut_ptr(),
            inp_handles.as_mut_ptr(),
            count as u32,
            bits,
        );
    }

    // Copy handles back
    for (i, h) in out_handles.into_iter().enumerate() {
        out[i].set_raw_handle(h);
    }
    for (i, h) in inp_handles.into_iter().enumerate() {
        inp[i].set_raw_handle(h);
    }
}

// Import declarations for all BN254FR functions
// Order matches C++ bn254fr.hpp initialize() for consistency
#[link(wasm_import_module = "bn254fr")]
extern "C" {
    // Memory management
    #[link_name = "bn254fr_alloc"]
    fn _bn254fr_alloc(fr: *mut bn254fr_t);

    #[link_name = "bn254fr_free"]
    fn _bn254fr_free(fr: *mut bn254fr_t);

    // Setters
    #[link_name = "bn254fr_set_u32"]
    fn _bn254fr_set_u32(out: *mut bn254fr_t, x: u32);

    #[link_name = "bn254fr_set_u64"]
    fn _bn254fr_set_u64(out: *mut bn254fr_t, x: u64);

    #[link_name = "bn254fr_set_bytes"]
    fn _bn254fr_set_bytes(out: *mut bn254fr_t, bytes: *const u8, len: u32, order: i32);

    #[link_name = "bn254fr_set_str"]
    fn _bn254fr_set_str(out: *mut bn254fr_t, s: *const i8, base: u32);

    // Getters
    #[link_name = "bn254fr_get_u64"]
    fn _bn254fr_get_u64(x: *const bn254fr_t) -> u64;

    // Copy / Print
    #[link_name = "bn254fr_copy"]
    fn _bn254fr_copy(dest: *mut bn254fr_t, src: *const bn254fr_t);

    #[link_name = "bn254fr_print"]
    fn _bn254fr_print(a: *const bn254fr_t, base: u32);

    // Constraint assertions
    #[link_name = "bn254fr_assert_equal"]
    fn _bn254fr_assert_equal(a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_assert_add"]
    fn _bn254fr_assert_add(out: *const bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_assert_mul"]
    fn _bn254fr_assert_mul(out: *const bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_assert_mulc"]
    fn _bn254fr_assert_mulc(out: *const bn254fr_t, a: *const bn254fr_t, k: *const bn254fr_t);

    // Checked bit operations
    #[link_name = "bn254fr_to_bits_checked"]
    fn _bn254fr_to_bits_checked(outs: *mut bn254fr_t, a: *const bn254fr_t, count: u32);

    #[link_name = "bn254fr_from_bits_checked"]
    fn _bn254fr_from_bits_checked(outs: *mut bn254fr_t, bits: *const bn254fr_t, count: u32);

    // Arithmetic
    #[link_name = "bn254fr_addmod"]
    fn _bn254fr_addmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_submod"]
    fn _bn254fr_submod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_mulmod"]
    fn _bn254fr_mulmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_divmod"]
    fn _bn254fr_divmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_invmod"]
    fn _bn254fr_invmod(out: *mut bn254fr_t, a: *const bn254fr_t);

    #[link_name = "bn254fr_negmod"]
    fn _bn254fr_negmod(out: *mut bn254fr_t, a: *const bn254fr_t);

    #[link_name = "bn254fr_powmod"]
    fn _bn254fr_powmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_idiv"]
    fn _bn254fr_idiv(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_irem"]
    fn _bn254fr_irem(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    // Comparisons
    #[link_name = "bn254fr_eq"]
    fn _bn254fr_eq(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_lt"]
    fn _bn254fr_lt(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_lte"]
    fn _bn254fr_lte(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_gt"]
    fn _bn254fr_gt(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_gte"]
    fn _bn254fr_gte(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_eqz"]
    fn _bn254fr_eqz(a: *const bn254fr_t) -> bool;

    // Logical operations
    #[link_name = "bn254fr_land"]
    fn _bn254fr_land(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    #[link_name = "bn254fr_lor"]
    fn _bn254fr_lor(a: *const bn254fr_t, b: *const bn254fr_t) -> bool;

    // Bitwise operations
    #[link_name = "bn254fr_band"]
    fn _bn254fr_band(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_bor"]
    fn _bn254fr_bor(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_bxor"]
    fn _bn254fr_bxor(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_bnot"]
    fn _bn254fr_bnot(out: *mut bn254fr_t, a: *const bn254fr_t);

    // Unchecked bit operations
    #[link_name = "bn254fr_to_bits"]
    fn _bn254fr_to_bits(outs: *mut bn254fr_t, a: *const bn254fr_t, count: u32);

    #[link_name = "bn254fr_from_bits"]
    fn _bn254fr_from_bits(outs: *mut bn254fr_t, bits: *const bn254fr_t, count: u32);

    // Shift operations
    #[link_name = "bn254fr_shrmod"]
    fn _bn254fr_shrmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    #[link_name = "bn254fr_shlmod"]
    fn _bn254fr_shlmod(out: *mut bn254fr_t, a: *const bn254fr_t, b: *const bn254fr_t);

    // Bigint operations (used by uint256)
    #[link_name = "bn254fr_bigint_mul_checked_no_carry"]
    fn _bn254fr_bigint_mul_checked_no_carry(
        out: *mut u64,
        a: *const u64,
        b: *const u64,
        count: u32,
    );

    #[link_name = "bn254fr_bigint_convert_to_proper_representation"]
    fn _bn254fr_bigint_convert_to_proper_representation(
        out: *mut u64,
        inp: *mut u64,
        count: u32,
        bits: u32,
    );
}
