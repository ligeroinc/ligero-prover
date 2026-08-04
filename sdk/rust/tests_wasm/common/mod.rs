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

//! Helpers shared by the VM test programs.
//!
//! Factored out here rather than repeated in every test file.

#![allow(dead_code)]

use ligetron::api::assert_one;
use ligetron::bn254fr::assert_equal_u32;
use ligetron::bn254fr_bigint::Bn254FrBigint;
use ligetron::ecc::coordinates::Affine;
use ligetron::ff::PrimeField;

/// Decodes a hex string into bytes. Panics on odd length or a non-hex digit.
pub fn hex_to_binary(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "invalid hex data size");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("invalid hex digit"))
        .collect()
}

/// Encodes bytes as a lowercase hex string.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Constrains two points to be equal.
pub fn assert_point_eq<F: PrimeField>(got: &Affine<F>, expected: &Affine<F>) {
    assert_equal_u32(&got.eq(expected), 1);
}

/// Host-side assertion used for checks on public data (lengths, hex strings).
pub fn check(cond: bool) {
    assert_one(i32::from(cond));
}

/// Builds a big integer from per-limb hex strings, least-significant limb first.
///
/// Goes through the public `set_bytes_little` rather than a limb-slice constructor: limb
/// handling is crate-internal, and this is the construction path an SDK user actually has.
/// Each limb becomes 8 little-endian bytes, so the limb count comes out equal to
/// `limbs.len()` — including any leading zero limbs the expected values carry.
pub fn bigint_from_limbs(limbs: &[&str]) -> Bn254FrBigint {
    let mut bytes: Vec<u8> = Vec::with_capacity(limbs.len() * 8);
    for limb in limbs {
        check(limb.len() <= 16);
        let padded = format!("{:0>16}", limb);
        let mut be = hex_to_binary(&padded);
        be.reverse();
        bytes.extend_from_slice(&be);
    }

    let mut res = Bn254FrBigint::new();
    res.set_bytes_little(&bytes);
    res
}

/// Constrains two big integers to be equal.
///
/// Goes through the public `eq`, which tolerates differing limb counts when the excess limbs
/// are zero, rather than comparing limbs directly.
pub fn assert_bigint_eq(a: &Bn254FrBigint, b: &Bn254FrBigint) {
    assert_equal_u32(&Bn254FrBigint::eq(a, b), 1);
}
