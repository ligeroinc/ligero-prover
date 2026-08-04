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

//! Keccak-256 as used by Ethereum.
//!
//! ## Overview
//!
//! This is the **Ethereum** variant — domain padding byte `0x01` — not NIST SHA3-256, which
//! pads with `0x06`. The two produce different digests for every input, so they are not
//! interchangeable: use this one for Ethereum addresses, event topics and ABI selectors.
//!
//! Rate is 136 bytes (1088-bit rate, 512-bit capacity) and the output is the first 256 bits
//! of the squeeze.
//!
//! Like [`crate::sha2`], this is ordinary integer code with no host calls. Under the Ligetron
//! toolchain it is transpiled into constraints; on the host it runs natively, which is why the
//! unit tests at the bottom of this file work under a plain `cargo test`.

/// Sponge rate in bytes: 1088-bit rate, 512-bit capacity.
const KECCAK256_RATE: usize = 136;

/// Round constants for the iota step.
const KECCAKF_RNDC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

/// Rotation offsets for the rho step.
const KECCAKF_ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

/// Lane permutation for the pi step.
const KECCAKF_PILN: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

/// The Keccak-f[1600] permutation, applied in place to the 25-lane state.
fn keccakf(s: &mut [u64; 25]) {
    let mut bc = [0u64; 5];

    for round in 0..24 {
        // Theta
        for i in 0..5 {
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];
        }
        for i in 0..5 {
            let t = bc[(i + 4) % 5] ^ bc[(i + 1) % 5].rotate_left(1);
            let mut j = 0;
            while j < 25 {
                s[j + i] ^= t;
                j += 5;
            }
        }

        // Rho and Pi
        let mut t = s[1];
        for i in 0..24 {
            let j = KECCAKF_PILN[i];
            let tmp = s[j];
            s[j] = t.rotate_left(KECCAKF_ROTC[i]);
            t = tmp;
        }

        // Chi
        let mut j = 0;
        while j < 25 {
            for i in 0..5 {
                bc[i] = s[j + i];
            }
            for i in 0..5 {
                s[j + i] ^= !bc[(i + 1) % 5] & bc[(i + 2) % 5];
            }
            j += 5;
        }

        // Iota
        s[0] ^= KECCAKF_RNDC[round];
    }
}

/// Keccak lanes are little-endian: byte `j` sits at bit `8*j`.
#[inline]
fn load64le(b: &[u8]) -> u64 {
    (b[0] as u64)
        | ((b[1] as u64) << 8)
        | ((b[2] as u64) << 16)
        | ((b[3] as u64) << 24)
        | ((b[4] as u64) << 32)
        | ((b[5] as u64) << 40)
        | ((b[6] as u64) << 48)
        | ((b[7] as u64) << 56)
}

#[inline]
fn store64le(b: &mut [u8], x: u64) {
    for i in 0..8 {
        b[i] = ((x >> (8 * i)) & 0xff) as u8;
    }
}

/// Computes the Ethereum Keccak-256 digest of `input` into `out`.
pub fn ligetron_keccak256(out: &mut [u8; 32], input: &[u8]) {
    let mut s = [0u64; 25];

    // Absorb full rate-sized blocks (17 little-endian lanes each).
    let mut chunks = input.chunks_exact(KECCAK256_RATE);
    for block in &mut chunks {
        for i in 0..KECCAK256_RATE / 8 {
            s[i] ^= load64le(&block[8 * i..]);
        }
        keccakf(&mut s);
    }

    // Final block: copy the tail, then pad10*1 (0x01 ... 0x80).
    let tail = chunks.remainder();
    let mut buf = [0u8; KECCAK256_RATE];
    buf[..tail.len()].copy_from_slice(tail);
    buf[tail.len()] = 0x01;
    // Must be |=, not =: when the tail is exactly RATE-1 bytes long the two padding bytes
    // land on the same byte and it has to end up 0x81.
    buf[KECCAK256_RATE - 1] |= 0x80;
    for i in 0..KECCAK256_RATE / 8 {
        s[i] ^= load64le(&buf[8 * i..]);
    }
    keccakf(&mut s);

    // Squeeze the first 256 bits = lanes s[0..3], little-endian.
    for i in 0..4 {
        store64le(&mut out[8 * i..], s[i]);
    }
}

/// Convenience wrapper returning the digest by value.
pub fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    ligetron_keccak256(&mut out, input);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; 32]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            hex(&keccak256(b"")),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn quick_brown_fox() {
        assert_eq!(
            hex(&keccak256(b"The quick brown fox jumps over the lazy dog")),
            "4d741b6f1eb29cb2a9b9911c82f56fa8d73b04959d3d9d222895df6c0b28aa15"
        );
    }

    /// The two padding bytes collide on the same byte at exactly RATE-1, which is the one
    /// length where writing `0x80` instead of OR-ing it would be wrong.
    ///
    /// Expected values generated from the C++ reference (`sdk/cpp/src/keccak256.cpp`)
    /// compiled and run natively, so these check Rust against the implementation being ported.
    #[test]
    fn padding_boundaries() {
        // 135 = RATE - 1: pad byte and final bit share buf[135], which must become 0x81.
        assert_eq!(
            hex(&keccak256(&[0x61u8; 135])),
            "34367dc248bbd832f4e3e69dfaac2f92638bd0bbd18f2912ba4ef454919cf446"
        );
        // 136 = RATE: one full absorbed block plus an all-padding final block.
        assert_eq!(
            hex(&keccak256(&[0x61u8; 136])),
            "a6c4d403279fe3e0af03729caada8374b5ca54d8065329a3ebcaeb4b60aa386e"
        );
        // 137 = RATE + 1: one absorbed block plus a one-byte tail.
        assert_eq!(
            hex(&keccak256(&[0x61u8; 137])),
            "d869f639c7046b4929fc92a4d988a8b22c55fbadb802c0c66ebcd484f1915f39"
        );
    }

    /// Multi-block input: exercises the absorb loop more than once.
    #[test]
    fn multi_block() {
        let input = [0x5au8; 300];
        assert_eq!(
            hex(&keccak256(&input)),
            "2d2ee5c87290a8a393018f7786d7f4c51ca54e5962cab9e42a3542afa767ff2a"
        );
        assert_eq!(
            hex(&keccak256(&input[..136])),
            "ddc757d2caa82320e140f35833c18e8cc3b230b2b9a48def3d98461ffae81716"
        );
    }
}
