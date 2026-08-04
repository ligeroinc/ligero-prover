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

//! Generic prime fields over [`Bn254FrBigint`](crate::bn254fr_bigint::Bn254FrBigint).
//!
//! ## Overview
//!
//! A 256-bit prime field — P-256's base field, Ed25519's scalar field, and so on — does not
//! fit in a single BN254 scalar, so elements are held as four 64-bit limbs and reduced
//! explicitly. This module turns that machinery into an ordinary-looking arithmetic type.
//!
//! A field is described by a zero-sized marker type implementing [`PrimeField`]; its only real
//! content is the modulus. [`FieldElement<F>`] is the value type, and supports `+ - * /` and
//! unary `-` on references.
//!
//! ## Lazy reduction
//!
//! Arithmetic leaves results in overflow form and defers the (expensive) reduction until it is
//! actually needed, tracking a bound on each limb's width. Reduction is triggered
//! automatically when an operation would otherwise exceed
//! [`MAX_BITS_COUNT`](crate::bn254fr_bigint::MAX_BITS_COUNT). Callers can force it with
//! [`FieldElement::reduce`], which the curve code does after every point operation to keep
//! widths bounded.

mod field_element;
mod storage;

pub use field_element::FieldElement;
pub use storage::PrimeFieldStorage;

use crate::bn254fr_bigint::Bn254FrBigint;

/// A prime field implemented over `bn254fr` big integers.
///
/// Implementors are zero-sized marker types. Use [`impl_prime_field!`] rather than writing the
/// impl by hand — the modulus has to live in a `static` inside the impl body, because Rust has
/// no generic statics and a `static` inside a generic function would be shared across every
/// instantiation.
pub trait PrimeField: 'static + Copy + Clone + core::fmt::Debug {
    /// Canonical modulus, decimal or `0x`-prefixed hex.
    const MODULUS_STR: &'static str;

    /// Canonical byte width. 32 for every field in this SDK.
    const NUM_BYTES: usize = 32;

    /// Bit width used by `to_bits`, rounded up to a byte boundary.
    const NUM_ROUNDED_BITS: usize = Self::NUM_BYTES * 8;

    /// The modulus in proper representation.
    ///
    /// Must return the same instance on every call.
    fn modulus() -> &'static Bn254FrBigint;
}

/// Builds the modulus big integer for a field from its decimal or hex string.
///
/// Used by [`impl_prime_field!`]; not intended to be called directly.
#[doc(hidden)]
pub fn build_modulus(s: &str) -> Bn254FrBigint {
    let u = crate::uint256::Uint256::from_str(s, 0);
    
    let mut v = Bn254FrBigint::with_limbs(crate::uint256::UINT256_NLIMBS);
    v.set(u.limbs_all(), crate::bn254fr_bigint::BASE_BITS_COUNT, true);
    v
}

/// Addresses of the leaked per-field modulus instances, so they can be reclaimed.
static MODULI: std::sync::Mutex<Vec<usize>> = std::sync::Mutex::new(Vec::new());

/// Builds a modulus, leaks it to obtain a `&'static`, and records it for
/// [`release_field_constants`].
///
/// Used by [`impl_prime_field!`]; not intended to be called directly.
#[doc(hidden)]
pub fn register_modulus(s: &str) -> &'static Bn254FrBigint {
    let leaked: &'static mut Bn254FrBigint = Box::leak(Box::new(build_modulus(s)));
    MODULI
        .lock()
        .unwrap()
        .push(leaked as *const Bn254FrBigint as usize);
    install_atexit_hook();
    leaked
}

/// Frees every cached field modulus.
///
/// **This must run before the program exits**, which is why
/// [`register_modulus`] installs an `atexit` hook to call it. Building a modulus constrains its
/// limbs, and the backend only commits a witness to the trace when it is *freed*
/// (`witness_manager::commit_release_witness`). A modulus that stays alive in a `static` for
/// the life of the program therefore contributes constraints whose trace rows never
/// materialise, and linear-constraint validation fails. The C++ gets this for free from static
/// destructors; Rust statics are never dropped.
///
/// Idempotent, and safe to call explicitly if a program bypasses the normal exit path.
pub fn release_field_constants() {
    let mut guard = MODULI.lock().unwrap();
    for p in guard.drain(..) {
        // SAFETY: every address in MODULI came from Box::leak in register_modulus, is only
        // recorded once, and is drained here so it cannot be freed twice.
        unsafe { drop(Box::from_raw(p as *mut Bn254FrBigint)) }
    }
}

extern "C" {
    fn atexit(cb: extern "C" fn()) -> i32;
}

extern "C" fn release_field_constants_hook() {
    release_field_constants();
}

fn install_atexit_hook() {
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        // wasi-libc runs registered handlers from `__wasm_call_dtors` when `_start` returns.
        unsafe { atexit(release_field_constants_hook) };
    });
}

/// Implements [`PrimeField`] for a marker type from its modulus string.
///
/// ```ignore
/// #[derive(Copy, Clone, Debug)]
/// pub struct P256Base;
/// impl_prime_field!(P256Base,
///     "0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
/// ```
#[macro_export]
macro_rules! impl_prime_field {
    ($ty:ty, $modulus:expr) => {
        impl $crate::ff::PrimeField for $ty {
            const MODULUS_STR: &'static str = $modulus;

            fn modulus() -> &'static $crate::bn254fr_bigint::Bn254FrBigint {
                // The static must live here, inside the non-generic impl body: a static
                // declared in a generic function is shared across all monomorphisations.
                //
                // `register_modulus` rather than a plain `LazyLock` value, because the cached
                // limbs must be *freed* before exit for their constraints to reach the trace —
                // see `release_field_constants`.
                static MODULUS: ::std::sync::OnceLock<
                    &'static $crate::bn254fr_bigint::Bn254FrBigint,
                > = ::std::sync::OnceLock::new();
                MODULUS.get_or_init(|| $crate::ff::register_modulus($modulus))
            }
        }
    };
}
