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
//! SHA-256 in circuit.
//!
//! The crate already has host-side unit tests for these vectors, but those run as ordinary
//! native arithmetic and never reach the constraint system. SHA-256 here is plain `u32`
//! arithmetic traced by the VM, so running it under the prover is the only way to check that the
//! traced form computes the same digest as the native one — and `check` is `assert_one`, a
//! circuit assertion, so the comparison itself is constrained.
//!
//! **The message bytes must be witnesses.** Hashing a literal costs 0 quadratic constraints:
//! the digest is folded at compile time and only the comparisons survive, so the round function
//! is never traced and the suite proves nothing about it. Every byte therefore goes through
//! `witness_cast_u32` first.
//!
//! The boundary walk below is the point of this suite. The padding used to test `len > 60`
//! against a length field written at offset 60, where FIPS 180-4 reserves bytes 56..63, so every
//! message of length 56..59 (mod 64) hashed to the wrong digest. Nothing in either SDK covered
//! that window.

#[path = "common/mod.rs"]
mod common;

use common::{check, hex_to_binary};

use ligetron::api::witness_cast_u32;
use ligetron::sha2::{ligetron_sha2_256, sha256};

/// Re-materialises `bytes` as witness values, so the hash cannot be constant-folded.
fn as_witness(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .map(|b| witness_cast_u32(u32::from(*b)) as u8)
        .collect()
}

fn do_test_sha256(msg: &[u8], expected_hex: &str) {
    let expected = hex_to_binary(expected_hex);
    check(expected.len() == 32);

    let msg = as_witness(msg);

    let mut out = [0u8; 32];
    ligetron_sha2_256(&mut out, &msg, msg.len() as u32);
    for i in 0..32 {
        check(out[i] == expected[i]);
    }

    // The convenience form must agree with the out-param form.
    let digest = sha256(&msg);
    for i in 0..32 {
        check(digest[i] == expected[i]);
    }

    // `len` must bound the read: trailing bytes past it cannot affect the digest.
    let mut padded = msg.clone();
    padded.extend_from_slice(&as_witness(&[0xa5; 7]));
    let mut out_padded = [0u8; 32];
    ligetron_sha2_256(&mut out_padded, &padded, msg.len() as u32);
    for i in 0..32 {
        check(out_padded[i] == expected[i]);
    }
}

fn main() {
    // Empty input: padding only.
    do_test_sha256(
        b"",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );

    do_test_sha256(
        b"abc",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );

    // FIPS 180-4 two-block vector: 56 bytes, so the 8-byte length field no longer fits.
    do_test_sha256(
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );

    // Walk the padding boundary a byte at a time. 55 is the largest message that still fits its
    // length field in the same block; 56 is the first that does not. 56..59 is the window the
    // old padding got wrong.
    const BOUNDARY: [(usize, &str); 10] = [
        (55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"),
        (56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"),
        (57, "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6"),
        (58, "d5c039b748aa64665782974ec3dc3025c042edf54dcdc2b5de31385b094cb678"),
        (59, "111bb261277afd65f0744b247cd3e47d386d71563d0ed995517807d5ebd4fba3"),
        (60, "11ee391211c6256460b6ed375957fadd8061cafbb31daf967db875aebd5aaad4"),
        (61, "35d5fc17cfbbadd00f5e710ada39f194c5ad7c766ad67072245f1fad45f0f530"),
        (62, "f506898cc7c2e092f9eb9fadae7ba50383f5b46a2a4fe5597dbb553a78981268"),
        (63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34"),
        (64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"),
    ];
    for (n, expected) in BOUNDARY {
        do_test_sha256(&vec![b'a'; n], expected);
    }
}
