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
pub(crate) struct bn254fr_t {
    pub handle: u64,
}

#[repr(C)]
pub struct Bn254Fr {
    data: bn254fr_t,
    constrained: AtomicBool,
}

/// Operations on a bare [`bn254fr_t`]
pub(crate) mod raw {
    use super::{
        bn254fr_t, _bn254fr_addmod, _bn254fr_assert_equal_bytes, _bn254fr_assert_equal_u32, _bn254fr_eq, _bn254fr_from_bits_checked, _bn254fr_set_bytes, _bn254fr_alloc, _bn254fr_assert_add, _bn254fr_assert_equal,
        _bn254fr_assert_equal_u64, _bn254fr_assert_mul, _bn254fr_assert_mulc, _bn254fr_copy,
        _bn254fr_divmod, _bn254fr_eqz, _bn254fr_free, _bn254fr_get_u64, _bn254fr_invmod,
        _bn254fr_lte, _bn254fr_mulmod, _bn254fr_negmod, _bn254fr_print, _bn254fr_set_u32,
        _bn254fr_set_u64, _bn254fr_shlmod, _bn254fr_submod, _bn254fr_to_bits_checked,
        _bn254fr_to_bytes,
    };

    /// Allocates a backend field element into `h`.
    pub(crate) fn alloc(h: &mut bn254fr_t) {
        unsafe { _bn254fr_alloc(h) }
    }

    /// Releases the element `h` refers to.
    pub(crate) fn free(h: &mut bn254fr_t) {
        unsafe { _bn254fr_free(h) }
    }

    /// `dst = src`, unconstrained.
    pub(crate) fn copy(dst: &mut bn254fr_t, src: &bn254fr_t) {
        unsafe { _bn254fr_copy(dst, src) }
    }

    /// Constrains `a == b`.
    pub(crate) fn assert_equal(a: &bn254fr_t, b: &bn254fr_t) {
        unsafe { _bn254fr_assert_equal(a, b) }
    }

    /// Constrains `x == y`.
    pub(crate) fn assert_equal_u32(x: &bn254fr_t, y: u32) {
        unsafe { _bn254fr_assert_equal_u32(x, y) }
    }

    /// Constrains `x == y`.
    pub(crate) fn assert_equal_u64(x: &bn254fr_t, y: u64) {
        unsafe { _bn254fr_assert_equal_u64(x, y) }
    }

    /// `h = value`, unconstrained.
    pub(crate) fn set_u32(h: &mut bn254fr_t, value: u32) {
        unsafe { _bn254fr_set_u32(h, value) }
    }

    /// `h = value`, unconstrained.
    pub(crate) fn set_u64(h: &mut bn254fr_t, value: u64) {
        unsafe { _bn254fr_set_u64(h, value) }
    }

    /// Reads the element's value out of circuit.
    ///
    /// This reads the *field element*, not the handle — the handle is only ever passed by
    /// address. Unconstrained: nothing binds the result to `h`.
    pub(crate) fn get_u64(h: &bn254fr_t) -> u64 {
        unsafe { _bn254fr_get_u64(h) }
    }

    /// Writes `out.len()` bytes of `x` in `order`.
    pub(crate) fn to_bytes(out: &mut [u8], x: &bn254fr_t, order: i32) {
        unsafe { _bn254fr_to_bytes(out.as_mut_ptr(), x, out.len() as u32, order) }
    }

    /// Decomposes `x` into `outs.len()` constrained bits.
    ///
    /// `outs` must already hold allocated handles.
    pub(crate) fn to_bits_checked(outs: &mut [bn254fr_t], x: &bn254fr_t) {
        unsafe { _bn254fr_to_bits_checked(outs.as_mut_ptr(), x, outs.len() as u32) }
    }

    /// Reads the element's value and binds it with a constraint: a `witness_cast_u64` paired
    /// with `assert_equal_u64`.
    pub(crate) fn get_u64_checked(h: &bn254fr_t) -> u64 {
        let res = crate::api::witness_cast_u64(get_u64(h));
        assert_equal_u64(h, res);
        res
    }

    /// An owned raw handle, freed on drop.
    ///
    /// The `bn254fr_t` analogue of [`Bn254Fr`](super::Bn254Fr) without the `constrained` flag,
    /// the alloc / use / free idiom the constrained helpers below rely on for their scratch
    /// values.
    pub(crate) struct Tmp(bn254fr_t);

    impl Tmp {
        /// Allocates a handle holding zero.
        ///
        /// The explicit `set_u32` matters: the backend recycles the underlying value, so a
        /// freshly allocated handle holds whatever the previous owner left there. Emits no
        /// constraint.
        pub(crate) fn new() -> Self {
            let mut h = bn254fr_t::default();
            alloc(&mut h);
            set_u32(&mut h, 0);
            Tmp(h)
        }

        pub(crate) fn from_u32(v: u32) -> Self {
            let mut t = Self::new();
            set_u32(&mut t.0, v);
            t
        }

        pub(crate) fn get(&self) -> &bn254fr_t {
            &self.0
        }

        pub(crate) fn get_mut(&mut self) -> &mut bn254fr_t {
            &mut self.0
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            free(&mut self.0)
        }
    }

    // Deref so `&tmp` / `&mut tmp` coerce to the handle, letting call sites pass a `Tmp`
    // anywhere a raw handle is expected.
    impl core::ops::Deref for Tmp {
        type Target = bn254fr_t;
        fn deref(&self) -> &bn254fr_t {
            &self.0
        }
    }

    impl core::ops::DerefMut for Tmp {
        fn deref_mut(&mut self) -> &mut bn254fr_t {
            &mut self.0
        }
    }

    // ---- unchecked primitives, straight to the host ----

    /// `x <= y`, out of circuit.
    pub(crate) fn lte(x: &bn254fr_t, y: &bn254fr_t) -> bool {
        unsafe { _bn254fr_lte(x, y) }
    }

    /// `h == 0`, out of circuit.
    pub(crate) fn is_zero(h: &bn254fr_t) -> bool {
        unsafe { _bn254fr_eqz(h) }
    }

    /// Composes a handle from constrained bits.
    pub(crate) fn from_bits_checked(out: &mut bn254fr_t, bits: &[bn254fr_t]) {
        unsafe { _bn254fr_from_bits_checked(out, bits.as_ptr(), bits.len() as u32) }
    }

    /// Sets `h` from `bytes` in `order` and binds it to them.
    pub(crate) fn set_bytes_checked(h: &mut bn254fr_t, bytes: &[u8], order: i32) {
        unsafe {
            _bn254fr_set_bytes(h, bytes.as_ptr(), bytes.len() as u32, order);
            _bn254fr_assert_equal_bytes(h, bytes.as_ptr(), bytes.len() as u32, order);
        }
    }

    /// `a == b`, out of circuit.
    pub(crate) fn eq(a: &bn254fr_t, b: &bn254fr_t) -> bool {
        unsafe { _bn254fr_eq(a, b) }
    }

    /// `out = a + b`, unconstrained.
    pub(crate) fn addmod(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe { _bn254fr_addmod(out, a, b) }
    }

    /// `out = a - b`, unconstrained.
    pub(crate) fn submod(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe { _bn254fr_submod(out, a, b) }
    }

    /// `out = a << b`, unconstrained.
    pub(crate) fn shlmod(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe { _bn254fr_shlmod(out, a, b) }
    }

    ///
    pub(crate) fn print(h: &bn254fr_t, base: u32) {
        unsafe { _bn254fr_print(h, base) }
    }

    // ---- checked arithmetic ----
    //
    // Each is the unchecked host op followed by its binding assertion. Raw handles carry no
    // `constrained` flag, so there is no clear/swap step here — that belongs to `Bn254Fr`.

    /// `out = a + b`, constrained.
    pub(crate) fn addmod_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe {
            _bn254fr_addmod(out, a, b);
            _bn254fr_assert_add(out, a, b);
        }
    }

    /// `out = a - b`, constrained.
    pub(crate) fn submod_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe {
            _bn254fr_submod(out, a, b);
            _bn254fr_assert_add(a, out, b);
        }
    }

    /// `out = a * b`, constrained.
    pub(crate) fn mulmod_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        unsafe {
            _bn254fr_mulmod(out, a, b);
            _bn254fr_assert_mul(out, a, b);
        }
    }

    /// `out = a / k` for constant `k`, constrained.
    pub(crate) fn divmod_constant_checked(out: &mut bn254fr_t, a: &bn254fr_t, k: &bn254fr_t) {
        unsafe {
            _bn254fr_divmod(out, a, k);
            _bn254fr_assert_mulc(a, out, k);
        }
    }

    /// `out = -a`, constrained.
    pub(crate) fn negmod_checked(out: &mut bn254fr_t, a: &bn254fr_t) {
        let zero = Tmp::from_u32(0);
        unsafe {
            _bn254fr_negmod(out, a);
            _bn254fr_assert_add(zero.get(), out, a);
        }
    }

    /// `out = 1` when `x == 0`, else `0`.
    pub(crate) fn eqz_checked(out: &mut bn254fr_t, x: &bn254fr_t) {
        let one = Tmp::from_u32(1);
        let zero = Tmp::from_u32(0);

        // inv = 1/x when x != 0, else 0.
        //
        // Both arms must emit *no* constraints, or the circuit's shape would depend on a secret
        // value — the verifier, which does not have that value, would then build a different
        // circuit and reject a valid proof. `bn254fr_invmod` and `bn254fr_set_u32` are both
        // bare host calls; the binding comes from the `x * out == 0` assertion below, which
        // runs on every path.
        //
        // The explicit zero is deliberate: `Tmp::new` does not initialise the value (the pooled
        // `mpz` is recycled), and leaving it unset would put that garbage in the trace.
        let mut inv = Tmp::new();
        if is_zero(x) {
            set_u32(inv.get_mut(), 0);
        } else {
            unsafe { _bn254fr_invmod(inv.get_mut(), x) }
        }

        // out = -x * inv + 1
        let mut neg_x = Tmp::new();
        negmod_checked(neg_x.get_mut(), x);
        let mut mul_res = Tmp::new();
        mulmod_checked(mul_res.get_mut(), neg_x.get(), inv.get());
        addmod_checked(out, mul_res.get(), one.get());

        // and x * out == 0
        let mut check = Tmp::new();
        mulmod_checked(check.get_mut(), x, out);
        assert_equal(check.get(), zero.get());
    }

    /// `out = 1` when `a == b`, else `0`.
    pub(crate) fn eq_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        let mut sub_res = Tmp::new();
        submod_checked(sub_res.get_mut(), a, b);
        eqz_checked(out, sub_res.get());
    }

    /// Logical AND of two circuit booleans.
    pub(crate) fn land_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        mulmod_checked(out, a, b)
    }

    /// Logical OR: `a + b - a*b`.
    pub(crate) fn lor_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t) {
        let mut mul_res = Tmp::new();
        let mut add_res = Tmp::new();
        mulmod_checked(mul_res.get_mut(), a, b);
        addmod_checked(add_res.get_mut(), a, b);
        submod_checked(out, add_res.get(), mul_res.get());
    }

    /// `out = 1` when `a < b` over `n_bits`.
    pub(crate) fn lt_checked(out: &mut bn254fr_t, a: &bn254fr_t, b: &bn254fr_t, n_bits: u32) {
        let mut x = Tmp::new();
        {
            let mut bits_pow = Tmp::from_u32(1);
            let n_bits_fr = Tmp::from_u32(n_bits);
            let src = Tmp::from_u32(1);
            unsafe { _bn254fr_shlmod(bits_pow.get_mut(), src.get(), n_bits_fr.get()) };

            let mut add_res = Tmp::new();
            addmod_checked(add_res.get_mut(), bits_pow.get(), a);
            submod_checked(x.get_mut(), add_res.get(), b);
        }

        // The comparison result is 1 - msb(x).
        let count = n_bits as usize + 1;
        let mut bits = vec![bn254fr_t::default(); count];
        for b in &mut bits {
            alloc(b);
        }
        to_bits_checked(&mut bits, x.get());
        let one = Tmp::from_u32(1);
        submod_checked(out, one.get(), &bits[n_bits as usize]);
        for b in &mut bits {
            free(b);
        }
    }

    /// `out = cond ? a1 : a0`, constrained.
    pub(crate) fn mux(out: &mut bn254fr_t, cond: &bn254fr_t, a0: &bn254fr_t, a1: &bn254fr_t) {
        let one = Tmp::from_u32(1);
        crate::api::assert_one(lte(cond, one.get()) as i32);

        // out = a0 + cond * (a1 - a0)
        let mut tmp = Tmp::new();
        submod_checked(tmp.get_mut(), a1, a0);
        let mut prod = Tmp::new();
        mulmod_checked(prod.get_mut(), tmp.get(), cond);
        addmod_checked(out, a0, prod.get());
    }

    /// Signed range check: proves `-2^(n_bits-1) <= x < 2^(n_bits-1)`.
    pub(crate) fn check_bits_signed(x: &bn254fr_t, n_bits: u32) {
        let mut pow = Tmp::from_u32(1);
        let shift = Tmp::from_u32(n_bits - 1);
        let src = Tmp::from_u32(1);
        unsafe { _bn254fr_shlmod(pow.get_mut(), src.get(), shift.get()) };

        let mut sum = Tmp::new();
        addmod_checked(sum.get_mut(), x, pow.get());
        check_bits(sum.get(), n_bits);
    }

    /// Writes `out.len()` bytes of `x` in `order`, re-materialising each byte as a witness and
    /// binding the result back to `x`.
    ///
    /// The unchecked [`to_bytes`] leaves the bytes as unconstrained host values, and public even
    /// when `x` is secret.
    pub(crate) fn to_bytes_checked(out: &mut [u8], x: &bn254fr_t, order: i32) {
        let len = out.len();
        assert!(len <= 32, "to_bytes_checked: at most 32 bytes");

        let mut unchecked = [0u8; 32];
        to_bytes(&mut unchecked[..len], x, order);
        for i in 0..len {
            out[i] = crate::api::witness_cast_u32(u32::from(unchecked[i])) as u8;
        }
        unsafe { _bn254fr_assert_equal_bytes(x, out.as_ptr(), len as u32, order) }
    }

    /// Splits an `n_bits + 1`-wide `sum` into its low `n_bits` (into `out`) and its top carry
    /// bit (returned).
    pub(crate) fn split_carry(out: &mut bn254fr_t, sum: &bn254fr_t, n_bits: u32) -> Tmp {
        let count = n_bits as usize + 1;
        let mut bits = vec![bn254fr_t::default(); count];
        for b in &mut bits {
            alloc(b);
        }
        to_bits_checked(&mut bits, sum);

        let mut carry = Tmp::new();
        copy(&mut carry, &bits[n_bits as usize]);
        assert_equal(&carry, &bits[n_bits as usize]);
        from_bits_checked(out, &bits[0..n_bits as usize]);

        for b in &mut bits {
            free(b);
        }
        carry
    }

    /// Range-checks `x` to `n_bits` and discards the bits.
    ///
    /// The decomposition itself is the constraint; the bit handles are scratch. Mirrors the
    /// alloc / use / free shape used for scratch throughout this module.
    pub(crate) fn check_bits(x: &bn254fr_t, n_bits: u32) {
        let mut bits = vec![bn254fr_t::default(); n_bits as usize];
        for b in &mut bits {
            alloc(b);
        }
        to_bits_checked(&mut bits, x);
        for b in &mut bits {
            free(b);
        }
    }
}

/// Constrained bit decomposition of a raw handle, bridged into owned [`Bn254Fr`] bits.
///
/// The host writes into a contiguous scratch array — it cannot write into a `[Bn254Fr]`, whose
/// stride is 16 — and each bit is then copied out with `bn254fr_copy` and bound with
/// `assert_equal`. That bridge is why no handle value is ever read.
pub(crate) fn bits_of(x: &bn254fr_t, count: usize) -> Vec<Bn254Fr> {
    let mut scratch = vec![bn254fr_t::default(); count];
    for b in &mut scratch {
        raw::alloc(b);
    }
    raw::to_bits_checked(&mut scratch, x);

    let mut bits: Vec<Bn254Fr> = Vec::with_capacity(count);
    for b in &mut scratch {
        let mut out = Bn254Fr::new();
        raw::copy(out.handle_mut(), b);
        raw::assert_equal(out.handle(), b);
        out.set_constrained(true);
        bits.push(out);
        raw::free(b);
    }
    bits
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
    /// A new element holding zero.
    ///
    /// The value is set explicitly: the backend recycles it, so a freshly allocated handle
    /// otherwise holds whatever the previous owner left behind. Emits no constraint — code that
    /// needs a *provable* zero must still constrain it, e.g. with [`assert_equal_u32`].
    #[inline(always)]
    pub fn new() -> Self {
        let mut out = Bn254Fr {
            data: bn254fr_t::default(),
            constrained: false.into(),
        };
        unsafe {
            _bn254fr_alloc(&mut out.data);
            _bn254fr_set_u32(&mut out.data, 0);
        };
        out
    }

    /// The underlying handle, by reference.
    ///
    /// Hands out a *borrow*, never the handle's value: callers pass this address straight to the
    /// C API. Returning the `u64` instead would
    /// load a host pointer, and the VM turns a load out of secret-marked memory into a witness
    /// carrying that pointer — see [`raw`].
    #[inline(always)]
    pub(crate) fn handle(&self) -> &bn254fr_t {
        &self.data
    }

    /// Mutable borrow of the underlying handle. See [`Bn254Fr::handle`].
    #[inline(always)]
    pub(crate) fn handle_mut(&mut self) -> &mut bn254fr_t {
        &mut self.data
    }

    /// Construct from u32 constant
    pub fn from_u32(value: u32) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_set_u32(&mut out.data, value);
        }
        out
    }

    /// Construct from u64 constant
    pub fn from_u64(value: u64) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
            _bn254fr_set_u64(&mut out.data, value);
        }
        out
    }

    /// Construct field element from a C-style string (decimal or hex with 0x prefix)
    pub fn from_c_str(str_ptr: *const i8) -> Self {
        let mut out = Bn254Fr::new();
        unsafe {
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

    /// Set field element to a u32 constant **and** constrain it to that literal.
    pub fn set_u32_checked(&mut self, value: u32) {
        self.set_u32(value);
        assert_equal_u32(self, value);
    }

    /// Set field element to a u64 constant **and** constrain it to that literal.
    pub fn set_u64_checked(&mut self, value: u64) {
        self.set_u64(value);
        assert_equal_u64(self, value);
    }

    /// Get field element as u64 (may truncate for large values)
    pub fn get_u64(&self) -> u64 {
        unsafe { _bn254fr_get_u64(&self.data) }
    }

    /// Read the value out as a `u64` and constrain the element to equal what was read.
    ///
    /// [`Bn254Fr::get_u64`] alone is an oracle read: the returned `u64` has no circuit
    /// relationship to `self`, so branching on it proves nothing. This binds the two, which is
    /// what makes the value usable as a witness. Truncates the same way for values above 2^64.
    pub fn get_u64_checked(&self) -> u64 {
        let res = crate::api::witness_cast_u64(self.get_u64());
        assert_equal_u64(self, res);
        res
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
    ///
    /// This is an unconstrained host query, so it takes `&self`: it reads the value and emits
    /// nothing. Use it to pick a branch, not to prove one — [`eqz_checked`] is the constrained
    /// form.
    pub fn is_zero(&self) -> bool {
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
    // `one` is CONSTRAINED to its literal. `from_u32` uses the unchecked setter
    // (`set_u32_checked` exists precisely to add the binding), so without the assertion below
    // it is a free witness -- and this function's soundness argument evaporates, because `out`
    // is `-x*inv + one` with both `inv` and `one` prover-chosen. The `x*out == 0` guard at the
    // end had the same defect and is now pinned to the literal directly. A caller asserting
    // `eqz(x) == 1` would otherwise have got it for any x. See A26.
    let one = Bn254Fr::from_u32(1);
    assert_equal_u32(&one, 1);

    // Compute inverse if x != 0, else use 0.
    //
    // The zero test goes through the `bn254fr_eqz` oracle rather than `get_u64`: the latter
    // truncates the field element to its low 64 bits, so any non-zero multiple of 2^64 would
    // be misread as zero and take the wrong branch.
    let mut inv = Bn254Fr::new();
    if !x.is_zero() {
        invmod(&mut inv, x);
    } else {
        // `Bn254Fr::new()` does NOT zero the value: the host's `bn254fr_alloc` hands back a
        // pooled `lazy_witness` carrying whatever the recycled `mpz` last held. Leaving `inv`
        // unset here puts that garbage into the witness trace, and because the pool's history
        // differs between the prover's stage 1 and stage 3, the two stages then encode
        // different rows and the verifier's Merkle root check fails.
        inv.set_u32(0);
    }

    // out = -x * inv + 1
    let mut neg_x = Bn254Fr::new();
    negmod_checked(&mut neg_x, x);

    let mut mul_res = Bn254Fr::new();
    mulmod_checked(&mut mul_res, &neg_x, &inv);

    addmod_checked(out, &mul_res, &one);

    // Assert x * out == 0
    let mut check = Bn254Fr::new();
    mulmod_checked(&mut check, x, out);
    assert_equal_u32(&check, 0);
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

/// Logical AND of two circuit booleans, with constraints.
///
/// Both inputs must already be constrained to 0 or 1; this is a plain multiplication.
pub fn land_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    mulmod_checked(out, a, b)
}

/// Logical OR of two circuit booleans, with constraints: `out = a + b - a*b`.
pub fn lor_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr) {
    let mut mul_res = Bn254Fr::new();
    let mut add_res = Bn254Fr::new();
    mulmod_checked(&mut mul_res, a, b);
    addmod_checked(&mut add_res, a, b);
    submod_checked(out, &add_res, &mul_res);
}

/// Logical NOT of a circuit boolean: `1 - v`.
///
/// A thin `submod_checked(out, one, v)`, factored out because ECDSA and EdDSA use it
/// constantly.
pub fn lnot(v: &Bn254Fr) -> Bn254Fr {
    let one = Bn254Fr::from_u32(1);
    let mut out = Bn254Fr::new();
    submod_checked(&mut out, &one, v);
    out
}

/// Left fold of [`land_checked`] over a list of circuit booleans.
///
/// Returns 1 when `vs` is empty, matching the identity of AND.
pub fn land_all(vs: &[&Bn254Fr]) -> Bn254Fr {
    match vs.split_first() {
        None => Bn254Fr::from_u32(1),
        Some((first, rest)) => {
            let mut acc = (*first).clone();
            for v in rest {
                let mut tmp = Bn254Fr::new();
                land_checked(&mut tmp, &acc, v);
                acc = tmp;
            }
            acc
        }
    }
}

/// `out = (a < b)`, treating both operands as `n_bits`-wide unsigned integers.
///
/// Computes `x = 2^n_bits + a - b`, decomposes `x` into `n_bits + 1` bits, and returns
/// `1 - msb(x)`: the borrow bit is clear exactly when `a < b`.
pub fn lt_checked(out: &mut Bn254Fr, a: &Bn254Fr, b: &Bn254Fr, n_bits: u32) {
    // x = 2^n_bits + a - b
    let mut x = Bn254Fr::new();
    {
        let mut bits_pow = Bn254Fr::from_u32(1);
        let n_bits_fr = Bn254Fr::from_u32(n_bits);
        bits_pow.shlmod(&n_bits_fr);

        let mut add_res = Bn254Fr::new();
        addmod_checked(&mut add_res, &bits_pow, a);
        submod_checked(&mut x, &add_res, b);
    }

    // The comparison result is 1 - msb(x).
    let bits = x.to_bits(n_bits as usize + 1);
    let one = Bn254Fr::from_u32(1);
    submod_checked(out, &one, &bits[n_bits as usize]);
}

/// Range check: decompose `x` into `n_bits` bits with constraints, then discard them.
///
/// This is how the SDK proves a value fits in a given width. The bits themselves are not
/// needed — only the constraints their decomposition emits.
pub fn check_bits(x: &Bn254Fr, n_bits: u32) {
    let _bits = x.to_bits(n_bits as usize);
}

/// Signed range check: proves `-2^(n_bits-1) <= x < 2^(n_bits-1)`.
///
/// Works by checking that `x + 2^(n_bits-1)` fits in `n_bits` bits.
pub fn check_bits_signed(x: &Bn254Fr, n_bits: u32) {
    let mut pow = Bn254Fr::from_u32(1);
    let shift = Bn254Fr::from_u32(n_bits - 1);
    pow.shlmod(&shift);

    let mut sum = Bn254Fr::new();
    addmod_checked(&mut sum, x, &pow);

    check_bits(&sum, n_bits);
}

/// Bit length of `n`, capped at 254: `floor(log2(n)) + 1`, and 0 for `n == 0`.
pub const fn bit_length(n: u32) -> u32 {
    let mut n_temp = n;
    let mut i = 0u32;
    while i < 254 {
        if n_temp == 0 {
            return i;
        }
        n_temp /= 2;
        i += 1;
    }
    254
}

/// `ceil(log2(n))`: the smallest `k` with `2^k >= n`. `ceil_log2(0) == ceil_log2(1) == 0`.
pub const fn ceil_log2(n: u32) -> u32 {
    if n <= 1 {
        0
    } else {
        bit_length(n - 1)
    }
}

/// Byte order for the import/export helpers: least-significant byte first.
pub const ORDER_LITTLE: i32 = -1;
/// Byte order for the import/export helpers: most-significant byte first.
pub const ORDER_BIG: i32 = 1;

/// Export a field element to bytes. Adds **no** constraints — the result is unbound to `x`
/// until the caller asserts it, e.g. with [`assert_equal_bytes`].
pub fn to_bytes(out: &mut [u8], x: &Bn254Fr, order: i32) {
    unsafe { _bn254fr_to_bytes(out.as_mut_ptr(), &x.data, out.len() as u32, order) }
}

/// Export a field element to bytes **and** constrain `x` to the bytes written.
///
/// The checked counterpart of [`to_bytes`]: each byte goes through `witness_cast_u32` so it
/// becomes a witness value rather than a host-side constant, then a single
/// [`assert_equal_bytes`] binds the whole buffer to `x`.
pub fn to_bytes_checked(out: &mut [u8], x: &Bn254Fr, order: i32) {
    let len = out.len();
    assert!(len <= 32, "to_bytes_checked: at most 32 bytes");

    let mut unchecked = [0u8; 32];
    to_bytes(&mut unchecked[..len], x, order);

    for i in 0..len {
        out[i] = crate::api::witness_cast_u32(u32::from(unchecked[i])) as u8;
    }

    assert_equal_bytes(x, out, order);
}

/// Constrain `x` to equal the literal `y`.
pub fn assert_equal_u32(x: &Bn254Fr, y: u32) {
    unsafe { _bn254fr_assert_equal_u32(&x.data, y) }
    x.set_constrained(true);
}

/// Constrain `x` to equal the literal `y`.
pub fn assert_equal_u64(x: &Bn254Fr, y: u64) {
    unsafe { _bn254fr_assert_equal_u64(&x.data, y) }
    x.set_constrained(true);
}

/// Constrain `x` to equal the integer encoded by `bytes` in the given order.
pub fn assert_equal_bytes(x: &Bn254Fr, bytes: &[u8], order: i32) {
    unsafe { _bn254fr_assert_equal_bytes(&x.data, bytes.as_ptr(), bytes.len() as u32, order) }
    x.set_constrained(true);
}

// Import declarations for all BN254FR functions
// One ordering exception worth noting: the
// `bn254fr_bigint_*` imports are declared alongside the types that consume them, in
// `bn254fr_bigint.rs` and `uint256.rs`, so that their slice-of-`Bn254Fr` wrappers can stay
// private to those modules.
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

    // Byte export and literal equality assertions
    #[link_name = "bn254fr_to_bytes"]
    fn _bn254fr_to_bytes(out: *mut u8, x: *const bn254fr_t, size: u32, order: i32);

    #[link_name = "bn254fr_assert_equal_u32"]
    fn _bn254fr_assert_equal_u32(x: *const bn254fr_t, y: u32);

    #[link_name = "bn254fr_assert_equal_u64"]
    fn _bn254fr_assert_equal_u64(x: *const bn254fr_t, y: u64);

    #[link_name = "bn254fr_assert_equal_bytes"]
    fn _bn254fr_assert_equal_bytes(x: *const bn254fr_t, bytes: *const u8, size: u32, order: i32);
}
