/*
 * Copyright (C) 2023-2025 Ligero, Inc.
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

//! Vectorized BN254 Scalar Field Operations for Ligetron

use std::ffi::CString;

/// A vectorized BN254 scalar field element container
///
/// This is an opaque handle to a vector of field elements managed by the Ligetron backend.
#[repr(C)]
pub struct VBn254Fr {
    vhandle: u32,
}

/// A constant value that can be used in vectorized operations
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VBn254FrConstant {
    data: [u32; 8],
}

impl Clone for VBn254Fr {
    fn clone(&self) -> Self {
        let mut out = VBn254Fr::new();
        unsafe {
            _vbn254fr_copy(&mut out, self);
        }
        out
    }
}

impl VBn254Fr {
    #[inline(always)]
    pub fn new() -> Self {
        let mut v = VBn254Fr { vhandle: 0 };
        unsafe {
            _vbn254fr_alloc(&mut v);
        }
        v
    }

    pub fn get_size() -> u64 {
        unsafe {
            _vbn254fr_get_size()
        }
    }

    #[inline(always)]
    /// Set vector from array of u32 values
    pub fn set_ui(&mut self, nums: &[u32]) {
        unsafe {
            _vbn254fr_set_ui(self, nums.as_ptr() as *mut u32, nums.len() as u64);
        }
    }

    #[inline(always)]
    /// Set all elements in vector to the same u32 scalar value
    pub fn set_ui_scalar(&mut self, num: u32) {
        unsafe {
            _vbn254fr_set_ui_scalar(self, num);
        }
    }

    /// Set vector from array of string values
    pub fn set_c_str(&mut self, c_ptrs: &[*const i8], base: i32) -> i32 {
        unsafe {
            _vbn254fr_set_str(self, c_ptrs.as_ptr(), c_ptrs.len() as u64, base)
        }
    }

    /// Set all elements in vector to the same string scalar value
    pub fn set_c_str_scalar(&mut self, c_str: *const i8, base: i32) -> i32 {
        unsafe {
            _vbn254fr_set_str_scalar(self, c_str, base)
        }
    }

    /// Set vector from array of string values
    pub fn set_str(&mut self, strings: &[&str], base: i32) -> i32 {
        let c_strings: Vec<CString> = strings.iter()
            .map(|s| CString::new(*s).expect("Error parsing numeric string"))
            .collect();
        let c_ptrs: Vec<*const i8> = c_strings.iter()
            .map(|cs| cs.as_ptr())
            .collect();
        unsafe {
            _vbn254fr_set_str(self, c_ptrs.as_ptr(), strings.len() as u64, base)
        }
    }

    /// Set all elements in vector to the same string scalar value
    pub fn set_str_scalar(&mut self, s: &str, base: i32) -> i32 {
        let c_str = CString::new(s).expect("Error parsing numeric string");
        unsafe {
            _vbn254fr_set_str_scalar(self, c_str.as_ptr(), base)
        }
    }

    /// Set vector from byte buffer
    pub fn set_bytes(&mut self, bytes: &[u8], count: u64) {
        unsafe {
            _vbn254fr_set_bytes(self, bytes.as_ptr(), bytes.len() as u64, count);
        }
    }

    /// Set all elements in vector to the same bytes scalar value
    pub fn set_bytes_scalar(&mut self, bytes: &[u8]) {
        unsafe {
            _vbn254fr_set_bytes_scalar(self, bytes.as_ptr(), bytes.len() as u64);
        }
    }

    /// Set vector from array of u32 values
    pub fn from_ui(nums: &[u32]) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        unsafe {
            _vbn254fr_set_ui(&mut out, nums.as_ptr() as *mut u32, nums.len() as u64);
        }
        out
    }

    /// Set all elements in vector to the same u32 scalar value
    pub fn from_ui_scalar(num: u32) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        unsafe {
            _vbn254fr_set_ui_scalar(&mut out, num);
        }
        out
    }

    /// Set vector from array of C-style string values.
    /// Base is determined from the prefix
    pub fn from_c_str(str_ptrs: &[*const i8]) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        out.set_c_str(str_ptrs, 0);
        out
    }

    /// Set all elements in vector to the same "C-style" string scalar value
    /// Base is determined from the prefix
    pub fn from_c_str_scalar(str_ptr: *const i8) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        out.set_c_str_scalar(str_ptr, 0);
        out
    }

    /// Set vector from array of string values.
    /// Base is determined from the prefix
    pub fn from_str(strings: &[&str]) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        out.set_str(strings, 0);
        out
    }

    /// Set all elements in vector to the same string scalar value
    /// Base is determined from the prefix
    pub fn from_str_scalar(s: &str) -> VBn254Fr {
        let mut out = VBn254Fr::new();
        out.set_str_scalar(s, 0);
        out
    }

    /// Print vector field elements for debugging
    pub fn print_dec(&self) {
        unsafe {
            _vbn254fr_print(self, 10);
        }
    }

    /// Print vector field elements for debugging
    pub fn print_hex(&self) {
        unsafe {
            _vbn254fr_print(self, 16);
        }
    }

    /// Decompose vector elements into bits
    pub fn bit_decompose(&self) -> Vec<VBn254Fr> {
        let mut bits: Vec<VBn254Fr> = vec![VBn254Fr::new(); 254];
        unsafe {
            _vbn254fr_bit_decompose(&mut bits[0], self);
        }
        bits
    }

    // ============= In-place Vector Operations =============

    /// Vector addition: self = self + x
    pub fn addmod_vec(&mut self, x: &VBn254Fr) {
        unsafe {
            _vbn254fr_addmod(self, self, x);
        }
    }

    /// Vector addition with constant: self = self + k
    pub fn addmod_constant(&mut self, k: &VBn254FrConstant) {
        unsafe {
            _vbn254fr_addmod_constant(self, self, k);
        }
    }

    /// Vector subtraction: self = self - x
    pub fn submod_vec(&mut self, x: &VBn254Fr) {
        unsafe {
            _vbn254fr_submod(self, self, x);
        }
    }

    /// Vector subtraction with constant: self = self - k
    pub fn submod_constant(&mut self, k: &VBn254FrConstant) {
        unsafe {
            _vbn254fr_submod_constant(self, self, k);
        }
    }

    /// Vector multiplication: self = self * x
    pub fn mulmod_vec(&mut self, x: &VBn254Fr) {
        unsafe {
            _vbn254fr_mulmod(self, self, x);
        }
    }

    /// Vector multiplication with constant: self = self * k
    pub fn mulmod_constant(&mut self, k: &VBn254FrConstant) {
        unsafe {
            _vbn254fr_mulmod_constant(self, self, k);
        }
    }

    /// Montgomery multiplication with constant: self = self * k (Montgomery form)
    pub fn mont_mul_constant(&mut self, k: &VBn254FrConstant) {
        unsafe {
            _vbn254fr_mont_mul_constant(self, self, k);
        }
    }

    /// Vector division: self = self / x
    pub fn divmod_vec(&mut self, x: &VBn254Fr) {
        unsafe {
            _vbn254fr_divmod(self, self, x);
        }
    }

    /// Assert two vectors are equal in the constraint system
    pub fn assert_equal(a: &VBn254Fr, b: &VBn254Fr) {
        unsafe {
            _vbn254fr_assert_equal(a, b);
        }
    }
}

// ============= Vector Arithmetic Operations =============

/// Vector addition: out = x + y
pub fn addmod_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    unsafe {
        _vbn254fr_addmod(out, x, y);
    }
}

/// Vector addition with constant: out = x + k
pub fn addmod_constant(out: &mut VBn254Fr, x: &VBn254Fr, k: &VBn254FrConstant) {
    unsafe {
        _vbn254fr_addmod_constant(out, x, k);
    }
}

/// Vector subtraction: out = x - y
pub fn submod_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    unsafe {
        _vbn254fr_submod(out, x, y);
    }
}

/// Vector subtraction with constant: out = x - k
pub fn submod_constant(out: &mut VBn254Fr, x: &VBn254Fr, k: &VBn254FrConstant) {
    unsafe {
        _vbn254fr_submod_constant(out, x, k);
    }
}

/// Constant subtraction with vector: out = k - x
pub fn constant_submod(out: &mut VBn254Fr, k: &VBn254FrConstant, x: &VBn254Fr) {
    unsafe {
        _vbn254fr_constant_submod(out, k, x);
    }
}

/// Vector multiplication: out = x * y
pub fn mulmod_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    unsafe {
        _vbn254fr_mulmod(out, x, y);
    }
}

/// Vector multiplication with constant: out = x * k
pub fn mulmod_constant(out: &mut VBn254Fr, x: &VBn254Fr, k: &VBn254FrConstant) {
    unsafe {
        _vbn254fr_mulmod_constant(out, x, k);
    }
}

/// Montgomery multiplication with constant: out = x * k (Montgomery form)
pub fn mont_mul_constant(out: &mut VBn254Fr, x: &VBn254Fr, k: &VBn254FrConstant) {
    unsafe {
        _vbn254fr_mont_mul_constant(out, x, k);
    }
}

/// Vector division: out = x / y
pub fn divmod_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    unsafe {
        _vbn254fr_divmod(out, x, y);
    }
}

// ============= Helper Operations =============

/// Vector XOR: out = x ^ y
pub fn bxor_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    let two = VBn254FrConstant::from_str("2");
    unsafe {
        _vbn254fr_mulmod(out, x, y);
        _vbn254fr_mulmod_constant(out, out, &two);
        _vbn254fr_submod(out, y, out);
        _vbn254fr_addmod(out, x, out);
    }
}

/// Vector not-equal: out = (x != y)
pub fn neq_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr) {
    let one = VBn254FrConstant::from_str("1");
    bxor_vec(out, x, y);
    unsafe {
        _vbn254fr_constant_submod(out, &one, out);
    }
}

/// Vector greater-than-or-equal with bit width: out = (x >= y)
pub fn gte_vec(out: &mut VBn254Fr, x: &VBn254Fr, y: &VBn254Fr, bit: usize) {
    let msb: usize = bit - 1;
    let one = VBn254FrConstant::from_str("1");
    let x_bits = x.bit_decompose();
    let y_bits = y.bit_decompose();

    let mut acc = VBn254Fr::new();
    let mut iacc = VBn254Fr::new();

    unsafe {
        _vbn254fr_constant_submod(&mut acc, &one, &y_bits[msb]);
        _vbn254fr_mulmod(&mut acc, &x_bits[msb], &acc);
        neq_vec(&mut iacc, &x_bits[msb], &y_bits[msb]);

        for i in (0..msb).rev() {
            // update acc
            _vbn254fr_constant_submod(out, &one, &y_bits[i]);
            _vbn254fr_mulmod(out, out, &x_bits[i]);
            _vbn254fr_mulmod(out, out, &iacc);
            _vbn254fr_addmod(&mut acc, &acc, out);

            // update iacc
            neq_vec(out, &x_bits[i], &y_bits[i]);
            _vbn254fr_mulmod(&mut iacc, &iacc, out);
        }
        _vbn254fr_addmod(out, &acc, &iacc);
    }
}

/// Conditional selection: out = cond ? a1 : a0 with constraints
pub fn mux_vec(out: &mut VBn254Fr, cond: &VBn254Fr, a0: &VBn254Fr, a1: &VBn254Fr) {
    let mut temp1 = VBn254Fr::new();
    let mut temp2 = VBn254Fr::new();

    submod_vec(&mut temp1, a1, a0);
    mulmod_vec(&mut temp2, cond, &temp1);
    addmod_vec(out, a0, &temp2);
}

pub fn mux2_vec(out: &mut VBn254Fr, s0: &VBn254Fr, s1: &VBn254Fr,
            a0: &VBn254Fr, a1: &VBn254Fr,
            a2: &VBn254Fr, a3: &VBn254Fr) {
    let mut temp1 = VBn254Fr::new();
    let mut temp2 = VBn254Fr::new();

    mux_vec(&mut temp1, s0, a0, a1);
    mux_vec(&mut temp2, s0, a2, a3);
    mux_vec(out, s1, &temp1, &temp2);
}

#[inline(always)]
pub fn oblivious_if_vec(out: &mut VBn254Fr, cond: bool, t: &VBn254Fr, f: &VBn254Fr) {
    let cond_fr = VBn254Fr::from_ui_scalar(cond as u32);
    mux_vec(out, &cond_fr, f, t);
}

impl Drop for VBn254Fr {
    fn drop(&mut self) {
        unsafe {
            _vbn254fr_free(self);
        }
    }
}

impl VBn254FrConstant {
    /// Create a new constant from string representation
    pub fn from_str_with_base(s: &str, base: i32) -> Self {
        let constant = VBn254FrConstant { data: [0; 8] };
        let c_str = CString::new(s).expect("Error parsing numeric string");
        unsafe {
            _vbn254fr_constant_set_str(&constant, c_str.as_ptr(), base);
        }
        constant
    }

    pub fn from_str(s: &str) -> Self {
        Self::from_str_with_base(s, 0)
    }
}

// Import declarations for all vectorized BN254FR functions
#[link(wasm_import_module = "vbn254fr")]
extern "C" {
    // Memory management
    #[link_name = "vbn254fr_get_size"]
    fn _vbn254fr_get_size() -> u64;

    #[link_name = "vbn254fr_alloc"]
    fn _vbn254fr_alloc(v: *mut VBn254Fr);

    #[link_name = "vbn254fr_free"]
    fn _vbn254fr_free(v: *mut VBn254Fr);

    // Initialization
    #[link_name = "vbn254fr_constant_set_str"]
    fn _vbn254fr_constant_set_str(k: *const VBn254FrConstant, s: *const i8, base: i32) -> i32;

    #[link_name = "vbn254fr_set_ui"]
    fn _vbn254fr_set_ui(v: *mut VBn254Fr, nums: *mut u32, len: u64);

    #[link_name = "vbn254fr_set_ui_scalar"]
    fn _vbn254fr_set_ui_scalar(v: *mut VBn254Fr, num: u32);

    #[link_name = "vbn254fr_set_str"]
    fn _vbn254fr_set_str(v: *mut VBn254Fr, strings: *const *const i8, len: u64, base: i32) -> i32;

    #[link_name = "vbn254fr_set_str_scalar"]
    fn _vbn254fr_set_str_scalar(v: *mut VBn254Fr, s: *const i8, base: i32) -> i32;

    #[link_name = "vbn254fr_set_bytes"]
    fn _vbn254fr_set_bytes(v: *mut VBn254Fr, bytes: *const u8, num_bytes: u64, count: u64);

    #[link_name = "vbn254fr_set_bytes_scalar"]
    fn _vbn254fr_set_bytes_scalar(v: *mut VBn254Fr, bytes: *const u8, num_bytes: u64);

    // Vector arithmetic
    #[link_name = "vbn254fr_addmod"]
    fn _vbn254fr_addmod(out: *mut VBn254Fr, x: *const VBn254Fr, y: *const VBn254Fr);

    #[link_name = "vbn254fr_addmod_constant"]
    fn _vbn254fr_addmod_constant(out: *mut VBn254Fr, x: *const VBn254Fr, k: *const VBn254FrConstant);

    #[link_name = "vbn254fr_submod"]
    fn _vbn254fr_submod(out: *mut VBn254Fr, x: *const VBn254Fr, y: *const VBn254Fr);

    #[link_name = "vbn254fr_submod_constant"]
    fn _vbn254fr_submod_constant(out: *mut VBn254Fr, x: *const VBn254Fr, k: *const VBn254FrConstant);

    #[link_name = "vbn254fr_constant_submod"]
    fn _vbn254fr_constant_submod(out: *mut VBn254Fr, k: *const VBn254FrConstant, x: *const VBn254Fr);

    #[link_name = "vbn254fr_mulmod"]
    fn _vbn254fr_mulmod(out: *mut VBn254Fr, x: *const VBn254Fr, y: *const VBn254Fr);

    #[link_name = "vbn254fr_mulmod_constant"]
    fn _vbn254fr_mulmod_constant(out: *mut VBn254Fr, x: *const VBn254Fr, k: *const VBn254FrConstant);

    #[link_name = "vbn254fr_mont_mul_constant"]
    fn _vbn254fr_mont_mul_constant(out: *mut VBn254Fr, x: *const VBn254Fr, k: *const VBn254FrConstant);

    #[link_name = "vbn254fr_divmod"]
    fn _vbn254fr_divmod(out: *mut VBn254Fr, x: *const VBn254Fr, y: *const VBn254Fr);

    // Misc operations
    #[link_name = "vbn254fr_copy"]
    fn _vbn254fr_copy(out: *mut VBn254Fr, input: *const VBn254Fr);

    #[link_name = "vbn254fr_print"]
    fn _vbn254fr_print(v: *const VBn254Fr, base: u32);

    #[link_name = "vbn254fr_bit_decompose"]
    fn _vbn254fr_bit_decompose(arr: *mut VBn254Fr, x: *const VBn254Fr);

    #[link_name = "vbn254fr_assert_equal"]
    fn _vbn254fr_assert_equal(x: *const VBn254Fr, y: *const VBn254Fr);
}