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
//! SHA-512 in circuit.
//!
//! The crate already has host-side unit tests for these vectors, but those run as ordinary
//! native arithmetic and never reach the constraint system. SHA-512 here is plain `u64`
//! arithmetic traced by the VM, so running it under the prover is the only way to check that the
//! traced form computes the same digest as the native one — and `check` is `assert_one`, a
//! circuit assertion, so the comparison itself is constrained.
//!
//! **The message bytes must be witnesses.** Hashing a literal costs 0 quadratic constraints:
//! the digest is folded at compile time and only the comparisons survive, so the round function
//! is never traced and the suite proves nothing about it. Every byte therefore goes through
//! `witness_cast_u32` first. The C++ suite hashes literals directly and has this blind spot.

#[path = "common/mod.rs"]
mod common;

use common::{check, hex_to_binary};

use ligetron::api::witness_cast_u32;
use ligetron::sha2::{ligetron_sha2_512, sha512};

/// Re-materialises `bytes` as witness values, so the hash cannot be constant-folded.
fn as_witness(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|b| witness_cast_u32(u32::from(*b)) as u8)
        .collect()
}

fn do_test_sha512(msg: &[u8], expected_hex: &str) {
    let expected = hex_to_binary(expected_hex);
    check(expected.len() == 64);

    let msg = as_witness(msg);

    let mut out = [0u8; 64];
    ligetron_sha2_512(&mut out, &msg, msg.len() as u32);
    for i in 0..64 {
        check(out[i] == expected[i]);
    }

    // The convenience form must agree with the out-param form.
    let digest = sha512(&msg);
    for i in 0..64 {
        check(digest[i] == expected[i]);
    }

    // `len` must bound the read: trailing bytes past it cannot affect the digest.
    let mut padded = msg.clone();
    padded.extend_from_slice(&as_witness(&[0xa5; 7]));
    let mut out_padded = [0u8; 64];
    ligetron_sha2_512(&mut out_padded, &padded, msg.len() as u32);
    for i in 0..64 {
        check(out_padded[i] == expected[i]);
    }
}

fn main() {
    // Empty input: padding only.
    do_test_sha512(
        b"",
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
          47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
    );

    do_test_sha512(
        b"abc",
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
          2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
    );

    // 112 bytes: two blocks, and the length that forces padding into a third.
    do_test_sha512(
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno\
ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
          501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    );
}
