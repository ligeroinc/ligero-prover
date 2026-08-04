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

//! ECDSA over P-256, against the BoringSSL FIPS vectors.
//!
//! Source:
//!   <https://boringssl.googlesource.com/boringssl/+/main/crypto/fipsmodule/ecdsa/ecdsa_sign_tests.txt>
//!
//! Digests in that set are 28, 32, 48 and 64 bytes wide (SHA-224 through SHA-512), while
//! `verify_digest` consumes exactly `SCALAR_BYTES`. Reconciling the two is the caller's job,
//! per SEC1 §4.1.4: take the leftmost `min(len, SCALAR_BYTES)` bytes — see `to_digest` below.
//! Note a 64-byte digest must be *truncated*, not reduced mod n; those give different scalars.
//!
//! This carries a representative subset of the ~40 BoringSSL positives (one per digest width,
//! plus the edge case where the digest exceeds the field modulus) rather than all of them —
//! each vector costs a full pair of scalar multiplications. The rejection cases are carried in
//! full, because the scalar-range and on-curve checks are precisely what this implementation
//! adds over the legacy one.

#[path = "common/mod.rs"]
mod common;

use common::hex_to_binary;

use ligetron::bn254fr::assert_equal_u32;
use ligetron::ecc::ecdsa::P256Ecdsa;

/// SEC1 §4.1.4: `e` is the leftmost `min(bitlen(n), bitlen(H))` bits of `H`. Taking the
/// leftmost `min(len, SCALAR_BYTES)` bytes and right-justifying them preserves the integer
/// value of a short digest and truncates a wide one, which is what the spec asks for.
fn to_digest(hex: &str) -> Vec<u8> {
    let raw = hex_to_binary(hex);
    let n = raw.len().min(P256Ecdsa::SCALAR_BYTES);
    let mut out = vec![0u8; P256Ecdsa::SCALAR_BYTES];
    out[P256Ecdsa::SCALAR_BYTES - n..].copy_from_slice(&raw[..n]);
    out
}

fn to_sig(r_hex: &str, s_hex: &str) -> Vec<u8> {
    let mut sig = hex_to_binary(r_hex);
    sig.extend_from_slice(&hex_to_binary(s_hex));
    assert_eq!(sig.len(), P256Ecdsa::SIGNATURE_BYTES);
    sig
}

fn run(pk_x: &str, pk_y: &str, digest: &str, r: &str, s: &str, expect_valid: bool) {
    let x = hex_to_binary(pk_x);
    let y = hex_to_binary(pk_y);

    let ec = P256Ecdsa::from_coords(&x, &y);
    let valid = ec.verify_digest(&to_sig(r, s), &to_digest(digest));

    assert_equal_u32(&valid, u32::from(expect_valid));
}

/// A signature the implementation must accept.
fn test_ecdsa_p256(pk_x: &str, pk_y: &str, digest: &str, r: &str, s: &str) {
    run(pk_x, pk_y, digest, r, s, true);
}

/// A signature the implementation must reject.
fn test_ecdsa_p256_reject(pk_x: &str, pk_y: &str, digest: &str, r: &str, s: &str) {
    run(pk_x, pk_y, digest, r, s, false);
}

const PK_X: &str = "1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83";
const PK_Y: &str = "ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9";
const DIGEST: &str = "44acf6b7e36c1342c2c5897204fe09504e1e2efb1a900377dbc4e7a6a133ec56";
const R: &str = "f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac";
const S: &str = "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903";

/// The group order, used to check that the range bound is exclusive.
const N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn main() {
    // ---- BoringSSL FIPS vectors (valid signatures) ----

    // 32-byte digest (SHA-256).
    test_ecdsa_p256(PK_X, PK_Y, DIGEST, R, S);

    // A digest that exceeds the field modulus, exercising the reduction on import.
    test_ecdsa_p256(
        PK_X,
        PK_Y,
        "ffffffff00000001000000000000000000000002ffffffffffffffffffffffff",
        R,
        "e19b0d2e78488e2b6f7168645d1f7529008662819a2d684ca15166d3a5142aa9",
    );

    // 28-byte digest (SHA-224), which must be right-justified rather than reduced.
    test_ecdsa_p256(
        "29578c7ab6ce0d11493c95d5ea05d299d536801ca9cbd50e9924e43b733b83ab",
        "08c8049879c6278b2273348474158515accaa38344106ef96803c5a05adc4800",
        "5e53611194b517b0ef4f704684850dfa387f99997d586d43c9e41530",
        "4a19274429e40522234b8785dc25fc524f179dcc95ff09b3c9770fc71f54ca0d",
        "58982b79a65b7320f5b92d13bdaecdd1259e760f0f718ba933fd098f6f75d4b7",
    );

    // 64-byte digest (SHA-512), which must be truncated rather than reduced.
    test_ecdsa_p256(
        "c62cc4a39ace01006ad48cf49a3e71466955bbeeca5d318d672695df926b3aa4",
        "c85ccf517bf2ebd9ad6a9e99254def0d74d1d2fd611e328b4a3988d4f045fe6f",
        "4cb0debbdb572d89e2e46dcc6c2c63ef032792683032ce965b3e7fa79e3282039a705acbcc7bd070\
         57a88b1e65852707934f10a67710ebefaa865201dfa6d4ff",
        "6e7ff8ec7a5c48e0877224a9fa8481283de45fcbee23b4c252b0c622442c26ad",
        "3dfac320b9c873318117da6bd856000a392b815659e5aa2a6a1852ccb2501df3",
    );

    // ---- Rejection cases (the BoringSSL set is positive-only) ----

    let zero = "0000000000000000000000000000000000000000000000000000000000000000";

    // r = 0 is outside [1, n-1].
    test_ecdsa_p256_reject(PK_X, PK_Y, DIGEST, zero, S);

    // s = 0 is outside [1, n-1].
    test_ecdsa_p256_reject(PK_X, PK_Y, DIGEST, R, zero);

    // r = n is outside [1, n-1]; the upper bound is exclusive.
    test_ecdsa_p256_reject(PK_X, PK_Y, DIGEST, N, S);

    // s = n is outside [1, n-1].
    test_ecdsa_p256_reject(PK_X, PK_Y, DIGEST, R, N);

    // Otherwise-valid signature with the low bit of s flipped.
    test_ecdsa_p256_reject(
        PK_X,
        PK_Y,
        DIGEST,
        R,
        "8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058902",
    );

    // An off-curve public key is deliberately NOT tested through verify_digest.
    //
    // verify_digest computes `pubkey_valid = on_curve(pubkey)` and ANDs it into the verdict,
    // which reads as "an off-curve key yields 0". In practice it cannot: the same unvalidated
    // key is also fed to scalar_mul, which ends in a hard `is_inf(acc) == 1` assertion. For a
    // point off the curve the MSM relation does not hold, so the circuit becomes unsatisfiable
    // before any verdict is produced — the proof cannot be built, rather than being built and
    // returning 0.
    //
    // That is not a soundness hole (an off-curve key still cannot yield acceptance), but the
    // `pubkey_valid` term is unobservable for exactly the input it exists to reject. The
    // on-curve predicate itself is covered directly in `p256_test.rs`.
}
