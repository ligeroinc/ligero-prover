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

//! Host oracles for elliptic curve arithmetic.
//!
//! ## Overview
//!
//! These are the `ecc` wasm import module: out-of-circuit helpers that compute a witness the
//! host can produce cheaply, which the circuit then *proves* with constraints built in
//! [`crate::ecc::curve`]. Nothing here is constrained on its own — a value returned by any
//! function in this module is untrusted until the caller has bound it.
//!
//! ## Secret marking
//!
//! Each oracle calls `memory().mark_secret_n()` on the buffer it writes, so the output is
//! marked secret and reads from it become witnesses — which is the point: the values are
//! secret-derived. The marking is sticky (only a store to those bytes clears it), so a buffer
//! that held oracle output stays marked until something overwrites it.
//!
//! That is harmless as long as nothing reads a *host handle* back out of such memory. It is why
//! [`crate::bn254fr::raw`] never reads a `bn254fr_t` value: a handle is a host pointer, and
//! turning one into a witness puts a process address into the proof. With handles only ever
//! passed by address, these buffers can be ordinary caller-owned slices.

/// Curve selector passed to every oracle below.
#[repr(i32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EccCurveType {
    P256 = 1,
    Secp256k1 = 2,
    Ed25519 = 3,
}

/// Number of bytes the host writes for each half of a decomposed scalar.
///
/// `scalar_decompose` bounds `|x|, |z| < sqrt(n)`, so 16 bytes suffice for all three
/// 256-bit curves. The host marks exactly this many bytes secret.
pub const DECOMPOSED_SCALAR_BYTES: usize = 16;


/// Computes `q = [s] p` out of circuit.
///
/// `p` and `q` are affine `x || y`, each coordinate little-endian and of equal width; `s` is
/// little-endian. The result is a bare witness: it proves nothing until the caller binds it,
/// which is what [`AffineCurve::scalar_mul`](crate::ecc::curve::AffineCurve::scalar_mul) does.
pub fn scalar_mul(curve: EccCurveType, q: &mut [u8], p: &[u8], s: &[u8]) {
    assert_eq!(q.len(), p.len(), "point buffers must have equal width");
    assert!(p.len() % 2 == 0, "point buffer must hold two coordinates");

    unsafe {
        _ecc_scalar_mul(curve as i32, q.as_mut_ptr(), p.as_ptr(), s.as_ptr(), s.len() as u32);
    }
}

/// Splits `k` into a signed rational reconstruction `k == x / z (mod n)` with
/// `|x|, |z| < sqrt(n)`.
///
/// Returns `(x_abs, x_positive, z_abs, z_positive)`, magnitudes little-endian. The sign flags
/// are returned as raw `i32` rather than `bool` deliberately: `scalar_mul` constrains their
/// booleanity in the integer domain (`assert_one(f * f == f)`), and a `bool` would make that
/// check vacuous.
///
/// This is what lets `scalar_mul` prove `[k]P = Q` as a 128-bit two-scalar multi-scalar
/// multiplication instead of 256 point doublings.
pub fn scalar_decompose(
    curve: EccCurveType,
    k: &[u8],
) -> ([u8; DECOMPOSED_SCALAR_BYTES], i32, [u8; DECOMPOSED_SCALAR_BYTES], i32) {
    // The host writes only as many bytes as each magnitude needs, so the buffers must start
    // zeroed — it does not pad them out.
    let mut x_abs = [0u8; DECOMPOSED_SCALAR_BYTES];
    let mut z_abs = [0u8; DECOMPOSED_SCALAR_BYTES];
    let mut x_positive: i32 = 0;
    let mut z_positive: i32 = 0;

    unsafe {
        _ecc_scalar_decompose(
            curve as i32,
            x_abs.as_mut_ptr(),
            &mut x_positive,
            z_abs.as_mut_ptr(),
            &mut z_positive,
            k.as_ptr(),
            k.len() as u32,
        );
    }

    (x_abs, x_positive, z_abs, z_positive)
}

/// Recovers the affine coordinates of a compressed point encoding.
///
/// Returns `(x, y, errc)`, both coordinates little-endian, `errc == 0` on success. A non-zero
/// `errc` still yields a well-formed pair of buffers; the caller folds the code into its
/// validity verdict rather than branching on it.
pub fn point_decompress(
    curve: EccCurveType,
    x: &mut [u8],
    y: &mut [u8],
    encoding: &[u8],
) -> i32 {
    assert_eq!(x.len(), y.len(), "coordinate buffers must have equal width");

    unsafe { _ecc_point_decompress(curve as i32, x.as_mut_ptr(), y.as_mut_ptr(), encoding.as_ptr()) }
}

#[link(wasm_import_module = "ecc")]
extern "C" {
    /// Decompose a scalar into a signed rational reconstruction
    #[link_name = "scalar_decompose"]
    fn _ecc_scalar_decompose(
        curve: i32,
        x_abs_bytes: *mut u8,
        x_positive: *mut i32,
        z_abs_bytes: *mut u8,
        z_positive: *mut i32,
        k_bytes: *const u8,
        num_k_bytes: u32,
    );

    /// Multiply a point by a scalar
    #[link_name = "scalar_mul"]
    fn _ecc_scalar_mul(
        curve: i32,
        q_bytes: *mut u8,
        p_bytes: *const u8,
        s_bytes: *const u8,
        num_s_bytes: u32,
    );

    /// Decompress a point encoding into affine coordinates
    #[link_name = "point_decompress"]
    fn _ecc_point_decompress(
        curve: i32,
        x_bytes: *mut u8,
        y_bytes: *mut u8,
        encoding_bytes: *const u8,
    ) -> i32;
}
