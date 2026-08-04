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

//! SHA-512 (FIPS 180-4).
//!
//! 128-byte blocks, 80 rounds, a 16-byte big-endian length field, and a 64-byte digest.

/// Round constants: the first 64 bits of the fractional parts of the cube roots of the first
/// 80 primes.
const K: [u64; 80] = [
    0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
    0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
    0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
    0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
    0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
    0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
    0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
    0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
    0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
    0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
    0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
    0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
    0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
    0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
    0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
    0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
    0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
    0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
    0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
    0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817,
];

/// Initial hash value: the first 64 bits of the fractional parts of the square roots of the
/// first eight primes.
const H0: [u64; 8] = [
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
];

#[inline]
fn gamma0(x: u64) -> u64 {
    x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7)
}

#[inline]
fn gamma1(x: u64) -> u64 {
    x.rotate_right(19) ^ x.rotate_right(61) ^ (x >> 6)
}

/// Compresses one 128-byte block into the state.
fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for i in 0..16 {
        let mut v: u64 = 0;
        for j in 0..8 {
            v = (v << 8) | block[8 * i + j] as u64;
        }
        w[i] = v;
    }
    for i in 16..80 {
        w[i] = gamma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(gamma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }

    let mut s = *state;
    for i in 0..80 {
        // The round is written as an explicit shift of the working array rather than a
        // rotating register assignment.
        let t0 = s[7]
            .wrapping_add(s[4].rotate_right(14) ^ s[4].rotate_right(18) ^ s[4].rotate_right(41))
            .wrapping_add(s[6] ^ (s[4] & (s[5] ^ s[6])))
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let t1 = (s[0].rotate_right(28) ^ s[0].rotate_right(34) ^ s[0].rotate_right(39))
            .wrapping_add(((s[0] | s[1]) & s[2]) | (s[0] & s[1]));
        s[3] = s[3].wrapping_add(t0);
        s[7] = t0.wrapping_add(t1);
        s.rotate_right(1);
    }

    for i in 0..8 {
        state[i] = state[i].wrapping_add(s[i]);
    }
}

/// Computes the SHA-512 digest of the first `len` bytes of `input` into `out`.
///
/// # Arguments
/// * `out` - Output buffer, exactly 64 bytes
/// * `input` - Input data, at least `len` bytes
/// * `len` - Number of bytes of `input` to hash
///
/// # Panics
/// If `len` exceeds `input.len()`.
///
/// [`ligetron_sha2_256`]: crate::sha2::ligetron_sha2_256
pub fn ligetron_sha2_512(out: &mut [u8; 64], input: &[u8], len: u32) {
    let input = &input[..len as usize];

    let mut state = H0;
    let mut bit_len: u64 = 0;

    let mut chunks = input.chunks_exact(128);
    for block in &mut chunks {
        compress(&mut state, block);
        bit_len = bit_len.wrapping_add(128 * 8);
    }
    let tail = chunks.remainder();

    let mut buf = [0u8; 128];
    buf[..tail.len()].copy_from_slice(tail);
    bit_len = bit_len.wrapping_add(tail.len() as u64 * 8);

    let mut len = tail.len();
    buf[len] = 0x80;
    len += 1;

    if len > 112 {
        // No room for the 16-byte length field: pad this block out and start a fresh one.
        for b in buf.iter_mut().skip(len) {
            *b = 0;
        }
        compress(&mut state, &buf);
        buf = [0u8; 128];
        len = 0;
    }
    for b in buf.iter_mut().take(112).skip(len) {
        *b = 0;
    }

    // 128-bit big-endian bit length; the high word is always zero here.
    buf[112..120].copy_from_slice(&0u64.to_be_bytes());
    buf[120..128].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut state, &buf);

    for i in 0..8 {
        out[8 * i..8 * i + 8].copy_from_slice(&state[i].to_be_bytes());
    }
}

/// Convenience wrapper returning the digest by value.
///
/// # Arguments
/// * `input` - Input data to hash
///
/// # Returns
/// SHA-512 hash as 64-byte array
pub fn sha512(input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    ligetron_sha2_512(&mut out, input, input.len() as u32);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(d: &[u8; 64]) -> String {
        d.iter().map(|b| format!("{:02x}", b)).collect()
    }

    #[test]
    fn empty_input() {
        assert_eq!(
            hex(&sha512(b"")),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
    }

    #[test]
    fn abc() {
        assert_eq!(
            hex(&sha512(b"abc")),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    /// FIPS 180-4 two-block message: 112 bytes, so the length field forces a second block.
    #[test]
    fn two_block_message() {
        let msg = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                    hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        assert_eq!(
            hex(&sha512(msg)),
            "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
             501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        );
    }

    /// The padding branch flips at 112 bytes: at or below it the 16-byte length field fits in
    /// the current block, above it a whole extra block is compressed.
    ///
    /// Expected values generated from the C++ reference (`sdk/cpp/src/sha512.cpp`) compiled
    /// and run natively, so these check Rust against the implementation being ported.
    #[test]
    fn padding_boundaries() {
        let cases: [(usize, &str); 6] = [
            (111, "fa9121c7b32b9e01733d034cfc78cbf67f926c7ed83e82200ef8681819692176\
                   0b4beff48404df811b953828274461673c68d04e297b0eb7b2b4d60fc6b566a2"),
            (112, "c01d080efd492776a1c43bd23dd99d0a2e626d481e16782e75d54c2503b5dc32\
                   bd05f0f1ba33e568b88fd2d970929b719ecbb152f58f130a407c8830604b70ca"),
            (113, "55ddd8ac210a6e18ba1ee055af84c966e0dbff091c43580ae1be703bdb85da31\
                   acf6948cf5bd90c55a20e5450f22fb89bd8d0085e39f85a86cc46abbca75e24d"),
            (127, "828613968b501dc00a97e08c73b118aa8876c26b8aac93df128502ab360f91ba\
                   b50a51e088769a5c1eff4782ace147dce3642554199876374291f5d921629502"),
            (128, "b73d1929aa615934e61a871596b3f3b33359f42b8175602e89f7e06e5f658a24\
                   3667807ed300314b95cacdd579f3e33abdfbe351909519a846d465c59582f321"),
            (129, "4f681e0bd53cda4b5a2041cc8a06f2eabde44fb16c951fbd5b87702f07aeab61\
                   1565b19c47fde30587177ebb852e3971bbd8d3fd30da18d71037dfbd98420429"),
        ];
        for (n, expected) in cases {
            assert_eq!(hex(&sha512(&vec![0x61u8; n])), expected, "length {}", n);
        }
    }
}
